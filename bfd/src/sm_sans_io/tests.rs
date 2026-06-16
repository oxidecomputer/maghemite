// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use proptest::prelude::*;
use test_strategy::Arbitrary;
use test_strategy::proptest;

const DETECT_MULT: u8 = 3;
const MIN_TX_RX: Duration = Duration::from_millis(50);

/// A fixed local config used by most tests.
fn local_info() -> PeerInfo {
    PeerInfo {
        desired_min_tx: MIN_TX_RX,
        required_min_rx: MIN_TX_RX,
        discriminator: 0x1111_1111,
        demand_mode: false,
        detection_multiplier: DETECT_MULT,
    }
}

/// Build a control packet carrying `peer_state` with sane interval fields.
fn packet_with(peer_state: BfdPeerState) -> packet::Control {
    let mut pkt = packet::Control {
        my_discriminator: 0x2222_2222,
        desired_min_tx: MIN_TX_RX.as_micros().try_into().unwrap(),
        required_min_rx: MIN_TX_RX.as_micros().try_into().unwrap(),
        detect_mult: DETECT_MULT,
        ..Default::default()
    };
    pkt.set_state(peer_state);
    pkt
}

// Test all possible (our_current_state, incoming_state_from_peer) combinations
// and ensure we transition as expected.
#[test]
fn transition_table_is_exhaustive_and_correct() {
    use BfdPeerState::*;
    use PacketReceivedResult::*;

    // (our state, received peer state) => (expected result, next state)
    let cases: &[(State, BfdPeerState, PacketReceivedResult, State)] = &[
        (State::Down, Down, DownToInit, State::Init),
        (State::Down, Init, DownToUp, State::Up),
        (State::Down, AdminDown, StateUnchanged, State::Down),
        (State::Down, Up, StateUnchanged, State::Down),
        (State::Init, AdminDown, InitToDown, State::Down),
        (State::Init, Down, StateUnchanged, State::Init),
        (State::Init, Init, InitToUp, State::Up),
        (State::Init, Up, InitToUp, State::Up),
        (State::Up, AdminDown, UpToDown, State::Down),
        (State::Up, Down, UpToDown, State::Down),
        (State::Up, Init, StateUnchanged, State::Up),
        (State::Up, Up, StateUnchanged, State::Up),
    ];

    let now = Instant::now();
    for &(start, peer_state, want_result, want_state) in cases {
        let mut sm = StateMachine::start(local_info(), now);
        sm.state = start;
        let got = sm.update_remote_peer_state(peer_state);
        assert_eq!(got, want_result, "result for ({start:?}, {peer_state:?})");
        assert_eq!(
            sm.state, want_state,
            "next state for ({start:?}, {peer_state:?})"
        );
    }
}

#[test]
fn poll_triggers_immediate_final_response() {
    let now = Instant::now();
    let mut sm = StateMachine::start(local_info(), now);

    let mut pkt = packet_with(BfdPeerState::Down);
    pkt.set_poll();
    sm.packet_received(pkt, now);

    // A final-flagged response must be queued and available immediately.
    let out = sm.packet_to_send(now).expect("a response is queued");
    assert!(out.r#final(), "poll response must set the final flag");
    assert!(!out.poll(), "poll response must not itself set poll");
}

#[test]
fn demand_mode_suppresses_unsolicited_sends() {
    let now = Instant::now();
    let mut sm = StateMachine::start(local_info(), now);

    let mut pkt = packet_with(BfdPeerState::Up);
    pkt.set_demand();
    sm.packet_received(pkt, now);

    // With the remote in demand mode we send nothing unsolicited, even
    // well past any send interval...
    let later = now + Duration::from_secs(10);
    assert!(sm.packet_to_send(later).is_none());

    // ...but a poll still elicits a response.
    let mut poll = packet_with(BfdPeerState::Up);
    poll.set_demand();
    poll.set_poll();
    sm.packet_received(poll, later);
    assert!(sm.packet_to_send(later).is_some());
}

#[test]
fn recv_deadline_expiry_reports_was_already_down() {
    let now = Instant::now();
    let mut sm = StateMachine::start(local_info(), now);

    // Drive to Up so the first expiry is an Up->Down transition.
    sm.packet_received(packet_with(BfdPeerState::Init), now);
    assert_eq!(sm.state(), BfdPeerState::Up);

    let past = sm.recv_deadline + Duration::from_millis(1);
    assert_eq!(
        sm.check_recv_deadline_expired(past),
        CheckRecvDeadlineResult::Expired {
            was_already_down: false
        },
    );
    assert_eq!(sm.state(), BfdPeerState::Down);

    // A second expiry while already Down reports was_already_down = true.
    let past2 = sm.recv_deadline + Duration::from_millis(1);
    assert_eq!(
        sm.check_recv_deadline_expired(past2),
        CheckRecvDeadlineResult::Expired {
            was_already_down: true
        },
    );
}

fn any_peer_state() -> impl Strategy<Value = BfdPeerState> {
    (0u8..=3).prop_map(|n| BfdPeerState::try_from(n).unwrap())
}

/// A single driver action. `Instant` can't be generated directly, so we
/// generate non-negative clock deltas and accumulate them — this keeps
/// `now` monotonically non-decreasing, as real time would be.
#[derive(Debug, Clone, Arbitrary)]
enum Op {
    RecvPacket {
        #[strategy(any_peer_state())]
        peer_state: BfdPeerState,
        poll: bool,
        demand: bool,
    },
    AdvanceClock {
        #[strategy(0u64..5_000_000)]
        micros: u64,
    },
    CheckDeadline,
    TakePacket,
}

/// Drives a single `StateMachine` through a sequence of `Op`s while
/// asserting per-step invariants.
struct Driver {
    sm: StateMachine,
    now: Instant,
}

impl Driver {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            sm: StateMachine::start(local_info(), now),
            now,
        }
    }

    fn apply(&mut self, op: &Op) {
        let before = self.sm.state;
        match op {
            Op::RecvPacket {
                peer_state,
                poll,
                demand,
            } => {
                let mut pkt = packet_with(*peer_state);
                let prev_num_poll_responses = self.sm.poll_responses.len();
                if *poll {
                    pkt.set_poll();
                }
                if *demand {
                    pkt.set_demand();
                }
                let prev_deadline = self.sm.recv_deadline;
                self.sm.packet_received(pkt, self.now);

                // Receiving a packet always re-arms the recv deadline
                // relative to `now`.
                assert!(self.sm.recv_deadline >= prev_deadline.min(self.now));

                // We should have enqueued a poll response if and only if `poll`
                // is true.
                let expected_num_poll_reponses = if *poll {
                    prev_num_poll_responses + 1
                } else {
                    prev_num_poll_responses
                };
                assert_eq!(
                    self.sm.poll_responses.len(),
                    expected_num_poll_reponses
                );
            }
            Op::AdvanceClock { micros } => {
                self.now += Duration::from_micros(*micros);
            }
            Op::CheckDeadline => {
                self.sm.check_recv_deadline_expired(self.now);
            }
            Op::TakePacket => {
                let _ = self.sm.packet_to_send(self.now);
            }
        }
        self.check_invariants(before);
    }

    fn check_invariants(&self, before: State) {
        // The implementation's `State` only ever names Down/Init/Up.
        let after = self.sm.state;
        assert!(legal_transition(before, after), "{before:?} -> {after:?}");

        // `next_deadline` is exactly the earliest of the recv deadline and
        // the next scheduled send.
        let want = match self.sm.next_send_at(self.now) {
            Some(send_at) => self.sm.recv_deadline.min(send_at),
            None => self.sm.recv_deadline,
        };
        assert_eq!(self.sm.next_deadline(self.now), want);
    }
}

/// The only edge the implementation must never take is Up -> Init; every
/// other (Down/Init/Up) pair is reachable per the RFC diagram.
fn legal_transition(before: State, after: State) -> bool {
    !matches!((before, after), (State::Up, State::Init))
}

#[proptest]
fn arbitrary_sequences_uphold_invariants(
    #[strategy(prop::collection::vec(any::<Op>(), 0..256))] ops: Vec<Op>,
) {
    let mut driver = Driver::new();
    for op in &ops {
        driver.apply(op);
    }
}

/// A pair of state machines sharing one virtual clock, "talking" to each other
/// as each end of a BFD session.
struct Sim {
    a: StateMachine,
    b: StateMachine,
    now: Instant,
    end: Instant,
}

impl Sim {
    fn new(run_for: Duration) -> Self {
        let now = Instant::now();
        let mut a_info = local_info();
        a_info.discriminator = 0xAAAA_AAAA;
        let mut b_info = local_info();
        b_info.discriminator = 0xBBBB_BBBB;
        Self {
            a: StateMachine::start(a_info, now),
            b: StateMachine::start(b_info, now),
            now,
            end: now + run_for,
        }
    }

    /// Advance one event. `deliver` decides whether packets sent this tick
    /// reach the far side (model loss / partition by returning false).
    fn step(&mut self, deliver: bool) {
        let now = self.now;
        self.a.check_recv_deadline_expired(now);
        self.b.check_recv_deadline_expired(now);

        if let Some(pkt) = self.a.packet_to_send(now)
            && deliver
        {
            self.b.packet_received(pkt, now);
        }
        if let Some(pkt) = self.b.packet_to_send(now)
            && deliver
        {
            self.a.packet_received(pkt, now);
        }

        // Jump to the next scheduled event, but always make forward
        // progress so a "ready now" deadline can't stall the loop.
        let next = self.a.next_deadline(now).min(self.b.next_deadline(now));
        self.now = next.max(now + Duration::from_micros(1));
    }

    fn run(&mut self, deliver: impl Fn(u64) -> bool) {
        let mut tick = 0u64;
        while self.now < self.end {
            self.step(deliver(tick));
            tick += 1;
        }
    }

    /// Advance by a fixed `dt`, delivering each direction's packet per the
    /// given flags.
    fn step_fixed(
        &mut self,
        dt: Duration,
        deliver_to_b: bool,
        deliver_to_a: bool,
    ) {
        let now = self.now;
        let from_a = self.a.packet_to_send(now);
        let from_b = self.b.packet_to_send(now);
        if let Some(pkt) = from_a
            && deliver_to_b
        {
            self.b.packet_received(pkt, now);
        }
        if let Some(pkt) = from_b
            && deliver_to_a
        {
            self.a.packet_received(pkt, now);
        }
        self.a.check_recv_deadline_expired(now);
        self.b.check_recv_deadline_expired(now);
        self.now += dt;
    }
}

/// A per-direction delivery schedule (`true` = deliver, `false` = drop) whose
/// runs of drops are always shorter than `DETECT_MULT`. Built by generating
/// gap sizes in `0..DETECT_MULT` and emitting that many drops before each
/// delivered packet, so no run of losses can reach the detection threshold.
fn bounded_loss_schedule() -> impl Strategy<Value = Vec<bool>> {
    prop::collection::vec(0u8..DETECT_MULT, 1..40).prop_map(|gaps| {
        let mut schedule = Vec::new();
        for gap in gaps {
            schedule.extend(std::iter::repeat_n(false, usize::from(gap)));
            schedule.push(true);
        }
        schedule
    })
}

#[test]
fn clean_channel_converges_to_up() {
    let mut sim = Sim::new(Duration::from_secs(2));
    sim.run(|_| true);
    assert_eq!(sim.a.state(), BfdPeerState::Up);
    assert_eq!(sim.b.state(), BfdPeerState::Up);
}

#[test]
fn total_partition_drives_both_down() {
    // Bring the session up on a clean channel first.
    let mut sim = Sim::new(Duration::from_secs(2));
    sim.run(|_| true);
    assert_eq!(sim.a.state(), BfdPeerState::Up);

    // Now drop everything for well over the detection time and confirm
    // both ends declare the session down.
    sim.end = sim.now + Duration::from_secs(2);
    sim.run(|_| false);
    assert_eq!(sim.a.state(), BfdPeerState::Down);
    assert_eq!(sim.b.state(), BfdPeerState::Down);
}

#[proptest]
fn bounded_consecutive_loss_keeps_session_up(
    // Independent, bounded-loss schedules for each direction. Because no run
    // of drops reaches detect_mult, the recv deadline is always reset in time
    // and the session must stay up for the whole run.
    #[strategy(bounded_loss_schedule())] to_b: Vec<bool>,
    #[strategy(bounded_loss_schedule())] to_a: Vec<bool>,
) {
    // One step per send interval, so each step is a transmission opportunity.
    let dt = local_info().required_min_rx;

    // Warm up on a clean channel until the session is established.
    let mut sim = Sim::new(Duration::ZERO);
    for _ in 0..4 {
        sim.step_fixed(dt, true, true);
    }
    prop_assert_eq!(sim.a.state(), BfdPeerState::Up);
    prop_assert_eq!(sim.b.state(), BfdPeerState::Up);

    // Drive the bounded-loss schedules; the session must never drop.
    let steps = to_b.len().max(to_a.len());
    for i in 0..steps {
        let deliver_to_b = to_b.get(i).copied().unwrap_or(true);
        let deliver_to_a = to_a.get(i).copied().unwrap_or(true);
        sim.step_fixed(dt, deliver_to_b, deliver_to_a);
        prop_assert_eq!(
            sim.a.state(),
            BfdPeerState::Up,
            "a down at step {}",
            i
        );
        prop_assert_eq!(
            sim.b.state(),
            BfdPeerState::Up,
            "b down at step {}",
            i
        );
    }
}
