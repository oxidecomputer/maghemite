// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::PeerInfo;
use crate::packet;
use mg_api_types::bfd::BfdPeerState;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketReceivedResult {
    DownToInit,
    DownToUp,
    InitToDown,
    InitToUp,
    UpToDown,
    StateUnchanged,
    UnknownPeerState,
}

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

    pub fn state(&self) -> BfdPeerState {
        self.state.into()
    }

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

        // If we've never sent a packet, we should start!
        let Some(last_unsolicited_send) = self.last_unsolicited_send else {
            return Some(now);
        };

        // TODO-correctness Should this consider local.desired_min_tx and/or add
        // jitter? See RFC 5880 §6.8.7
        Some(last_unsolicited_send + self.remote.required_min_rx)
    }

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

    pub fn packet_received(
        &mut self,
        packet: packet::Control,
        now: Instant,
    ) -> PacketReceivedResult {
        self.update_remote_peer_info(&packet);
        self.recv_deadline = next_recv_deadline(&self.local, now);

        if packet.poll() {
            let mut pkt = self.make_packet_to_send();
            pkt.set_final();
            self.poll_responses.push_back(pkt);
        }

        match packet.state() {
            packet::State::Peer(peer_state) => {
                self.update_remote_peer_state(peer_state)
            }
            packet::State::Unknown(_) => PacketReceivedResult::UnknownPeerState,
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

    fn update_remote_peer_state(
        &mut self,
        peer_state: BfdPeerState,
    ) -> PacketReceivedResult {
        let transition = match (self.state, peer_state) {
            (State::Down, BfdPeerState::Down) => {
                Some((State::Init, PacketReceivedResult::DownToInit))
            }
            (State::Down, BfdPeerState::Init) => {
                Some((State::Up, PacketReceivedResult::DownToUp))
            }
            (State::Down, BfdPeerState::AdminDown | BfdPeerState::Up) => None,

            (State::Init, BfdPeerState::AdminDown) => {
                Some((State::Down, PacketReceivedResult::InitToDown))
            }
            (State::Init, BfdPeerState::Down) => None,
            (State::Init, BfdPeerState::Init | BfdPeerState::Up) => {
                Some((State::Up, PacketReceivedResult::InitToUp))
            }

            (State::Up, BfdPeerState::AdminDown | BfdPeerState::Down) => {
                Some((State::Down, PacketReceivedResult::UpToDown))
            }
            (State::Up, BfdPeerState::Init | BfdPeerState::Up) => None,
        };
        if let Some((our_next_state, result)) = transition {
            self.state = our_next_state;
            result
        } else {
            PacketReceivedResult::StateUnchanged
        }
    }

    fn make_packet_to_send(&self) -> packet::Control {
        // TODO-correctness Should this set detect_mult to
        // `self.local.detection_multiplier`? The old state machine didn't, but
        // this means we always send the default value instead of our config.
        let mut pkt = packet::Control {
            desired_min_tx: self.local.desired_min_tx.as_micros() as u32,
            required_min_rx: self.local.required_min_rx.as_micros() as u32,
            my_discriminator: self.local.discriminator,
            your_discriminator: self.remote.discriminator,
            ..Default::default()
        };
        pkt.set_state(self.state.into());
        pkt
    }
}

fn next_recv_deadline(local: &PeerInfo, last_recv: Instant) -> Instant {
    // TODO-correctness Should this be using the remote desired_min_tx and
    // detection_multiplier instead of our local one? Check RFC 5880 §6.8.4
    last_recv + local.required_min_rx * u32::from(local.detection_multiplier)
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
