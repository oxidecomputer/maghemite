// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Primary handle to a single BFD session.
//!
//! One BFD session involves four tokio tasks: a listener task owned by the
//! `Dispatcher` (shared with all other sessions that have the same local
//! listening address), and three tasks specific to the session owned by
//! [`Session`]:
//!
//! 1. A `DriverTask` that feeds events to the "sans I/O" state machine
//! 2. An `EgressTask` that sends outgoing packets on a UDP socket
//! 3. A `RibTask` that synchronizes the nexthop shutdown state with `rdb`
//!
//! When the `Session` is shut down, all three of these tasks are `abort()`'d,
//! which means they must be cancel safe. The driver and egress tasks are
//! entirely stateless (they touch no persistent storage, and the only in-memory
//! state they have is shared with each other - nothing visible outside the
//! session). The `RibTask` uses `tokio::spawn_blocking()` to bridge back into
//! the synchronous `rdb` world; a `spawn_blocking()` task cannot be canceled,
//! so if the `RibTask` is cancelled while performing an rdb update, that rdb
//! update will run to completion.

use crate::AddPeerRequest;
use crate::egress::EgressTask;
use crate::rib::RibTask;
use crate::single_hop_egress_src_port::SingleHopEgressSrcPort;
use crate::sm::CheckRecvDeadlineResult;
use crate::sm::StateMachine;
use bfd::PeerInfo;
use bfd::SessionCounters;
use bfd::packet;
use mg_api_types::bfd::BfdPeerState;
use mg_api_types::bfd::SessionMode;
use slog::Logger;
use slog::warn;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Depth of the driver -> egress channel. This is intentionally small: we
/// expect the egress task to promptly send any packets we ask it to send, and
/// if that task starts to get behind, the driver will drop packets rather than
/// creating an arbitrarily-long queue.
const EGRESS_CHANNEL_DEPTH: usize = 4;

pub struct Session {
    required_rx_micros: u64,
    detection_threshold: NonZeroU8,
    mode: SessionMode,
    state_rx: watch::Receiver<BfdPeerState>,
    counters: Arc<SessionCounters>,

    driver_task: JoinHandle<()>,
    egress_task: JoinHandle<()>,
    rib_task: JoinHandle<()>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver_task.abort();
        self.egress_task.abort();
        self.rib_task.abort();
    }
}

impl Session {
    pub(crate) fn new(
        db: rdb::Db,
        rq: AddPeerRequest,
        egress_src_port: Arc<SingleHopEgressSrcPort>,
        listener_rx: mpsc::Receiver<packet::Control>,
        log: &Logger,
    ) -> Self {
        let AddPeerRequest {
            remote_addr,
            listen_addr,
            required_rx_micros,
            detection_threshold,
            mode,
        } = rq;

        let local_peer_info = PeerInfo::with_random_discriminator(
            Duration::from_micros(required_rx_micros),
            detection_threshold,
        );
        let sm = StateMachine::start(local_peer_info, Instant::now());
        let counters = Arc::new(SessionCounters::default());
        let (state_tx, state_rx) = watch::channel(sm.state());

        let log = log.new(slog::o!(
            "local-addr" => listen_addr.to_string(),
            "remote-addr" => remote_addr.to_string(),
            "component" => bfd::COMPONENT_BFD,
            "module" => bfd::MOD_DAEMON,
            "unit" => bfd::UNIT_PEER,
        ));

        // Spawn the three primary tasks for this session.
        let rib_task = tokio::spawn(
            RibTask::new(remote_addr.ip(), state_tx.subscribe()).run(db),
        );

        let (egress_tx, egress_rx) = mpsc::channel(EGRESS_CHANNEL_DEPTH);
        let egress_task = tokio::spawn(
            EgressTask::new(
                egress_rx,
                listen_addr.ip(),
                remote_addr,
                mode,
                egress_src_port,
                Arc::clone(&counters),
                log.clone(),
            )
            .run(),
        );

        let driver_task = tokio::spawn(
            DriverTask {
                sm,
                counters: Arc::clone(&counters),
                remote_addr,
                listener_rx,
                egress_tx,
                state_tx,
                log,
            }
            .run(),
        );

        Self {
            required_rx_micros,
            detection_threshold,
            mode,
            state_rx,
            counters,
            driver_task,
            egress_task,
            rib_task,
        }
    }

    pub fn state(&self) -> BfdPeerState {
        *self.state_rx.borrow()
    }

    pub fn counters(&self) -> &Arc<SessionCounters> {
        &self.counters
    }

    pub fn required_rx_micros(&self) -> u64 {
        self.required_rx_micros
    }

    pub fn detection_threshold(&self) -> NonZeroU8 {
        self.detection_threshold
    }

    pub fn mode(&self) -> SessionMode {
        self.mode
    }
}

enum Event {
    /// A deadline requested by the state machine has elapsed.
    DeadlineExpired,

    /// We received an incoming packet from the listener channel.
    PacketReceived(packet::Control),

    /// The listener channel closed: this fires when the Dispatcher tears down
    /// our associated listener task, so the session is being removed.
    ShuttingDown,
}

struct DriverTask {
    sm: StateMachine,
    counters: Arc<SessionCounters>,
    remote_addr: SocketAddr,
    listener_rx: mpsc::Receiver<packet::Control>,
    egress_tx: mpsc::Sender<Vec<u8>>,
    state_tx: watch::Sender<BfdPeerState>,
    log: Logger,
}

impl DriverTask {
    async fn run(mut self) {
        loop {
            let state_before = self.sm.state();

            match self.wait_for_event(Instant::now()).await {
                Event::PacketReceived(pkt) => {
                    self.count_incoming(&pkt);
                    self.sm.packet_received(pkt, Instant::now());
                }
                Event::DeadlineExpired => {
                    self.handle_deadline();
                }
                Event::ShuttingDown => return,
            }

            if self.sm.state() != state_before {
                self.on_transition();
            }
            self.flush_outgoing_packets();
        }
    }

    async fn wait_for_event(&mut self, now: Instant) -> Event {
        let deadline = self.sm.next_deadline(now);

        // Cancel-safety: both `recv()` and `sleep_until()` are cancel safe
        // (`recv()` per its docs; `sleep_until()` because we want to discard it
        // if we receive a packet). Neither arm contains an `.await`, avoiding
        // any opportunity for futurelock.
        tokio::select! {
            // Prefer servicing an already-queued incoming packet over acting on
            // the deadline: if the deadline is a recv timeout, an available
            // packet should reset it; if it's a transmit deadline, we'll still
            // send on the next iteration.
            biased;

            maybe_pkt = self.listener_rx.recv() => match maybe_pkt {
                Some(pkt) => Event::PacketReceived(pkt),
                None => Event::ShuttingDown,
            },

            () = tokio::time::sleep_until(deadline.into()) => {
                Event::DeadlineExpired
            }
        }
    }

    fn handle_deadline(&mut self) {
        match self.sm.check_recv_deadline_expired(Instant::now()) {
            CheckRecvDeadlineResult::Expired { was_already_down } => {
                self.counters
                    .timeout_expired
                    .fetch_add(1, Ordering::Relaxed);
                if !was_already_down {
                    warn!(
                        self.log, "recv timeout expired; peer is down";
                        "peer" => %self.remote_addr,
                    );
                }
            }
            CheckRecvDeadlineResult::NotExpired => (),
        }
    }

    fn on_transition(&mut self) {
        let new_state = self.sm.state();
        let counter = match new_state {
            BfdPeerState::AdminDown | BfdPeerState::Down => {
                &self.counters.transition_to_down
            }
            BfdPeerState::Init => &self.counters.transition_to_init,
            BfdPeerState::Up => &self.counters.transition_to_up,
        };
        counter.fetch_add(1, Ordering::Relaxed);

        // Publishing the new state on the watch channel makes it available to
        // both outside consumers (via `Session::state()`) and will wake up the
        // `RibTask` to sync with the rib db, if needed.
        self.state_tx.send_replace(new_state);
    }

    fn flush_outgoing_packets(&mut self) {
        while let Some(pkt) = self.sm.packet_to_send(Instant::now()) {
            // We don't want to block on this channel: if the egress task has
            // fallen behind, we don't want to pause the driver. Instead, we'll
            // drop packets if we've already queued up `EGRESS_CHANNEL_DEPTH`
            // that are waiting to go out.
            match self.egress_tx.try_send(pkt.to_bytes()) {
                Ok(()) => (),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.counters
                        .control_packet_send_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Egress task is gone; we're tearing down. The next
                    // `wait_for_event` will observe shutdown as well.
                }
            }
        }
    }

    fn count_incoming(&self, pkt: &packet::Control) {
        self.counters
            .control_packets_received
            .fetch_add(1, Ordering::Relaxed);
        let counter = match pkt.state() {
            packet::State::Peer(BfdPeerState::AdminDown) => {
                &self.counters.admin_down_status_received
            }
            packet::State::Peer(BfdPeerState::Down) => {
                &self.counters.down_status_received
            }
            packet::State::Peer(BfdPeerState::Init) => {
                &self.counters.init_status_received
            }
            packet::State::Peer(BfdPeerState::Up) => {
                &self.counters.up_status_received
            }
            packet::State::Unknown(_) => &self.counters.unknown_status_received,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
