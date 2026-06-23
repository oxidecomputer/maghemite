// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use bfd::PeerInfo;
use bfd::packet;
use mg_api_types::bfd::BfdPeerState;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

/// Return value of [`StateMachine::check_recv_deadline_expired()`].
///
/// If [`CheckRecvDeadlineResult::Expired`] is returned, the state machine
/// transitioned to the down state (unless it was already down, which is visible
/// via the inner `was_already_down` value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckRecvDeadlineResult {
    Expired { was_already_down: bool },
    NotExpired,
}

/// This state machine implements the BFD state machine. The following is taken
/// directly from RFC 5880. The arrows indicate the state machine transition
/// that is taken when a packet containing the peer state on the label is
/// received.
///
/// ```text
///                             +--+
///                             |  | UP, ADMIN DOWN, TIMER
///                             |  V
///                     DOWN  +------+  INIT
///              +------------|      |------------+
///              |            | DOWN |            |
///              |  +-------->|      |<--------+  |
///              |  |         +------+         |  |
///              |  |                          |  |
///              |  |               ADMIN DOWN,|  |
///              |  |ADMIN DOWN,          DOWN,|  |
///              |  |TIMER                TIMER|  |
///              V  |                          |  V
///            +------+                      +------+
///       +----|      |                      |      |----+
///   DOWN|    | INIT |--------------------->|  UP  |    |INIT, UP
///       +--->|      | INIT, UP             |      |<---+
///            +------+                      +------+
/// ```
pub struct StateMachine {
    state: State,
    local: PeerInfo,
    remote: PeerInfo,
    last_unsolicited_send: Option<Instant>,
    recv_deadline: Instant,
    poll_responses: VecDeque<packet::Control>,
}

impl StateMachine {
    /// Start the state machine.
    ///
    /// `now` must be the current time; it's used to calculate the initial recv
    /// timeout.
    pub fn start(local_peer_info: PeerInfo, now: Instant) -> Self {
        let recv_deadline = next_recv_deadline(&local_peer_info, now);
        Self {
            state: State::Down,
            local: local_peer_info,
            remote: PeerInfo::default(),
            last_unsolicited_send: None,
            recv_deadline,
            poll_responses: VecDeque::new(),
        }
    }

    /// Current session state.
    pub fn state(&self) -> BfdPeerState {
        self.state.into()
    }

    /// Get the next deadline; this will be the sooner of the recv deadline
    /// timeout and when [`Self::packet_to_send()`] could have a packet to send.
    ///
    /// If we currently have a pending packet to send, returns `now`.
    pub fn next_deadline(&self, now: Instant) -> Instant {
        if let Some(next_send_at) = self.next_send_at(now) {
            Instant::min(self.recv_deadline, next_send_at)
        } else {
            self.recv_deadline
        }
    }

    fn next_send_at(&self, now: Instant) -> Option<Instant> {
        // If we have a poll response to send, we're ready now.
        if !self.poll_responses.is_empty() {
            return Some(now);
        }

        if self.remote.demand_mode {
            // Unsolicited packets are not sent in demand mode.
            return None;
        }

        // RFC 5880 §6.8.3: a Required Min RX Interval of zero means the remote
        // does not want us to send any periodic control packets. Without this
        // guard the `last_unsolicited_send + 0` below is always in the past and
        // we'd transmit as fast as we're polled.
        if self.remote.required_min_rx.is_zero() {
            return None;
        }

        // If we've never sent a packet, we should start!
        let Some(last_unsolicited_send) = self.last_unsolicited_send else {
            return Some(now);
        };

        // TODO-correctness Several issues with this, I think, per RFC 5880:
        //
        // * §6.8.3: MUST set `DesiredMinTxInterval` to at least 1sec if the
        //   session state is not `Up`
        // * §6.8.7: MUST take larger of `DesiredMinTxInterval` and
        //   `RemoteMinRxInterval`
        // * §6.8.7: MUST apply per-packet jitter of 0-25%
        Some(last_unsolicited_send + self.remote.required_min_rx)
    }

    /// Get the next packet to send.
    ///
    /// If this method returns `Some(_)`, the state machine discards this packet
    /// under the assumption that the caller is responsible for sending it (or
    /// enqueueing it to be sent).
    pub fn packet_to_send(&mut self, now: Instant) -> Option<packet::Control> {
        // Do we need to respond to a poll?
        if let Some(packet) = self.poll_responses.pop_front() {
            return Some(packet);
        }

        // We only have a packet of our own to send if time has advanced past
        // our `next_send`.
        match self.next_send_at(now) {
            Some(t) if now >= t => {
                self.last_unsolicited_send = Some(now);
                Some(self.make_packet_to_send())
            }
            Some(_) | None => None,
        }
    }

    /// Check whether the deadline for receiving packets from our peer has
    /// passed.
    pub fn check_recv_deadline_expired(
        &mut self,
        now: Instant,
    ) -> CheckRecvDeadlineResult {
        if now >= self.recv_deadline {
            self.recv_deadline = next_recv_deadline(&self.local, now);
            let was_already_down = if self.state == State::Down {
                true
            } else {
                self.state = State::Down;
                false
            };
            CheckRecvDeadlineResult::Expired { was_already_down }
        } else {
            CheckRecvDeadlineResult::NotExpired
        }
    }

    /// Handle an incoming packet from our peer.
    pub fn packet_received(&mut self, packet: packet::Control, now: Instant) {
        self.update_remote_peer_info(&packet);
        self.recv_deadline = next_recv_deadline(&self.local, now);

        if packet.poll() {
            let mut pkt = self.make_packet_to_send();
            pkt.set_final();
            self.poll_responses.push_back(pkt);
        }

        match packet.state() {
            packet::State::Peer(peer_state) => {
                self.update_remote_peer_state(peer_state);
            }
            packet::State::Unknown(_) => {
                // We don't know how to update the remote peer state, so we do
                // nothing other than bump our "we received a packet" bits
                // above.
            }
        }
    }

    fn update_remote_peer_info(&mut self, packet: &packet::Control) {
        self.remote = PeerInfo {
            desired_min_tx: Duration::from_micros(packet.desired_min_tx.into()),
            required_min_rx: Duration::from_micros(
                packet.required_min_rx.into(),
            ),
            discriminator: packet.my_discriminator,
            demand_mode: packet.demand(),
            detection_multiplier: packet.detect_mult,
        };
    }

    fn update_remote_peer_state(&mut self, remote_peer_state: BfdPeerState) {
        self.state = match (self.state, remote_peer_state) {
            (State::Down, BfdPeerState::Down) => State::Init,
            (State::Down, BfdPeerState::Init) => State::Up,
            (State::Down, BfdPeerState::AdminDown | BfdPeerState::Up) => {
                State::Down
            }

            (State::Init, BfdPeerState::AdminDown) => State::Down,
            (State::Init, BfdPeerState::Down) => State::Init,
            (State::Init, BfdPeerState::Init | BfdPeerState::Up) => State::Up,

            (State::Up, BfdPeerState::AdminDown | BfdPeerState::Down) => {
                State::Down
            }
            (State::Up, BfdPeerState::Init | BfdPeerState::Up) => State::Up,
        };
    }

    fn make_packet_to_send(&self) -> packet::Control {
        // TODO-correctness Should this set detect_mult to
        // `self.local.detection_multiplier`? The old state machine didn't, but
        // this means we always send the default value instead of our config.
        let mut pkt = packet::Control {
            // The wire fields are u32 microseconds. Saturate rather than let
            // the cast silently wrap for intervals above ~71.6 minutes.
            desired_min_tx: micros_u32(self.local.desired_min_tx),
            required_min_rx: micros_u32(self.local.required_min_rx),
            my_discriminator: self.local.discriminator,
            your_discriminator: self.remote.discriminator,
            ..Default::default()
        };
        pkt.set_state(self.state.into());
        pkt
    }
}

/// Convert a duration to microseconds as a `u32` wire field, saturating
/// instead of wrapping for durations beyond `u32::MAX` microseconds.
fn micros_u32(d: Duration) -> u32 {
    u32::try_from(d.as_micros()).unwrap_or(u32::MAX)
}

fn next_recv_deadline(local: &PeerInfo, last_recv: Instant) -> Instant {
    // TODO-correctness Similar issues here as the next send timer per RFC 5880
    // §6.8.4:
    //
    // * in async mode, calculation should be max(local min rx, remote min tx) *
    //   remote detection multiplier
    // * in demand mode calculation should be max(local min tx, remote min rx) *
    //   local detection multiplier
    //
    // I don't think we support demand mode? But that means this calculation is
    // wrong for async (wrong multiplier, isn't considering remote min tx)?
    let recv_timeout = local
        .required_min_rx
        .saturating_mul(u32::from(local.detection_multiplier.get()));

    // TODO-correctness What should we do on "overflows an Instant"? That should
    // be _very_ impossible given any reasonable values for `last_recv` (which
    // are always from `Instant::now()` and `recv_timeout`, but someone passing
    // a truly absurdly large `required_min_rx` could maybe cause problems? For
    // now, we'll fall back to a hardcoded, large recv deadline if this addition
    // overflows, but the actual value we pick is a total WAG.
    last_recv
        .checked_add(recv_timeout)
        .unwrap_or_else(|| last_recv + Duration::from_secs(60))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Down,
    Init,
    Up,
}

impl From<State> for BfdPeerState {
    fn from(state: State) -> Self {
        match state {
            State::Down => Self::Down,
            State::Init => Self::Init,
            State::Up => Self::Up,
        }
    }
}

#[cfg(test)]
mod tests;
