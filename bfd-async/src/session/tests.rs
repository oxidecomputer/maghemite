// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Unit tests for the session [`DriverTask`] in isolation.
//!
//! The driver is exercised with no real sockets: we feed it incoming packets on
//! a channel and observe its outputs on the egress channel and the state watch.
//!
//! We do not test the egress and RIB tasks (nor even spawn them) - they have
//! their own separate unit tests.

use super::*;
use crate::wait_for_condition;
use bfd::DEFAULT_DETECT_MULTIPLIER;
use bfd::packet::Control;
use mg_common::parse;
use mg_common::sockaddr;
use slog::Discard;
use slog::o;
use tokio::time::timeout;

struct Harness {
    driver: JoinHandle<()>,
    listener_tx: mpsc::Sender<Control>,
    egress_rx: mpsc::Receiver<Vec<u8>>,
    state_rx: watch::Receiver<BfdPeerState>,
    counters: Arc<SessionCounters>,
}

// Spawn a driver task and wrap the extra bits we need in a test harness.
//
// Most tests pass a very large `required_rx` to avoid any flakiness introduced
// by spurious recv timeouts. Only tests exercising recv timeouts specifically
// pass a "reasoanble" value here.
fn spawn_driver(required_rx: Duration) -> Harness {
    let (listener_tx, listener_rx) = mpsc::channel(8);
    let (egress_tx, egress_rx) = mpsc::channel(EGRESS_CHANNEL_DEPTH);

    let sm = StateMachine::start(
        PeerInfo::with_random_discriminator(
            required_rx,
            DEFAULT_DETECT_MULTIPLIER,
        ),
        Instant::now(),
    );
    let (state_tx, state_rx) = watch::channel(sm.state());
    let counters = Arc::new(SessionCounters::default());

    let driver = tokio::spawn(
        DriverTask {
            sm,
            counters: Arc::clone(&counters),
            remote_addr: sockaddr!("127.0.0.1:3784"),
            listener_rx,
            egress_tx,
            state_tx,
            log: Logger::root(Discard, o!()),
        }
        .run(),
    );

    Harness {
        driver,
        listener_tx,
        egress_rx,
        state_rx,
        counters,
    }
}

/// An incoming control packet advertising peer state `state`. Uses
/// `Control::default()`, which sets `required_min_rx == 0`, so once the driver
/// has received one of these the state machine stops scheduling periodic egress
/// sends, which would just be noise for most tests.
fn peer_packet(state: BfdPeerState) -> Control {
    let mut pkt = Control::default();
    pkt.set_state(state);
    pkt
}

/// Wait for the driver to publish `expected` on the state watch.
async fn wait_for_state(h: &Harness, expected: BfdPeerState) {
    wait_for_condition(Duration::from_secs(5), || {
        *h.state_rx.borrow() == expected
    })
    .await
    .unwrap_or_else(|e| panic!("never reached {expected:?}: {e}"));
}

/// Drive a freshly-started (Down) session up to `Up` via the normal handshake:
/// peer Down (-> Init), then peer Init (-> Up). Sent back-to-back so the
/// pre-`Up` window stays short.
async fn bring_to_up(h: &Harness) {
    h.listener_tx
        .send(peer_packet(BfdPeerState::Down))
        .await
        .unwrap();
    h.listener_tx
        .send(peer_packet(BfdPeerState::Init))
        .await
        .unwrap();
    wait_for_state(h, BfdPeerState::Up).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn exits_when_listener_channel_closes() {
    let h = spawn_driver(Duration::from_secs(3600));
    drop(h.listener_tx);
    timeout(Duration::from_secs(5), h.driver)
        .await
        .expect("driver did not exit after listener channel closed")
        .expect("driver panicked");
}

#[tokio::test(flavor = "multi_thread")]
async fn emits_outgoing_control_packet() {
    let mut h = spawn_driver(Duration::from_secs(3600));
    // A freshly-started session has a packet to send immediately, so the driver
    // should hand a valid control packet to the egress channel.
    let bytes = timeout(Duration::from_secs(5), h.egress_rx.recv())
        .await
        .expect("timed out waiting for outgoing packet")
        .expect("egress channel closed");
    Control::from_bytes(&bytes).expect("driver emitted a valid control packet");
}

#[tokio::test(flavor = "multi_thread")]
async fn counts_incoming_packets() {
    let h = spawn_driver(Duration::from_secs(3600));

    // `Control::default()` carries the peer's `Down` state.
    h.listener_tx.send(Control::default()).await.unwrap();

    wait_for_condition(Duration::from_secs(5), || {
        h.counters.control_packets_received.load(Ordering::Relaxed) == 1
    })
    .await
    .unwrap();
    assert_eq!(h.counters.down_status_received.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_down_init_up_publishes_each_state() {
    let h = spawn_driver(Duration::from_secs(3600));

    // Down: peer Down -> we go Init.
    h.listener_tx
        .send(peer_packet(BfdPeerState::Down))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Init).await;
    assert_eq!(h.counters.transition_to_init.load(Ordering::Relaxed), 1);

    // Init: peer Init -> we go Up.
    h.listener_tx
        .send(peer_packet(BfdPeerState::Init))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Up).await;
    assert_eq!(h.counters.transition_to_up.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn down_to_up_directly() {
    let h = spawn_driver(Duration::from_secs(3600));

    // From Down, a peer advertising Init takes us straight to Up.
    h.listener_tx
        .send(peer_packet(BfdPeerState::Init))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Up).await;
    assert_eq!(h.counters.transition_to_up.load(Ordering::Relaxed), 1);
    assert_eq!(h.counters.transition_to_init.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn up_to_down_on_peer_down() {
    let h = spawn_driver(Duration::from_secs(3600));
    bring_to_up(&h).await;

    h.listener_tx
        .send(peer_packet(BfdPeerState::Down))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Down).await;
    assert_eq!(h.counters.transition_to_down.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn up_to_down_on_peer_admin_down() {
    let h = spawn_driver(Duration::from_secs(3600));
    bring_to_up(&h).await;

    h.listener_tx
        .send(peer_packet(BfdPeerState::AdminDown))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Down).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn init_to_down_on_peer_admin_down() {
    let h = spawn_driver(Duration::from_secs(3600));

    h.listener_tx
        .send(peer_packet(BfdPeerState::Down))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Init).await;

    h.listener_tx
        .send(peer_packet(BfdPeerState::AdminDown))
        .await
        .unwrap();
    wait_for_state(&h, BfdPeerState::Down).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_state_that_does_not_advance_is_a_no_op() {
    let h = spawn_driver(Duration::from_secs(3600));

    // From Down, a peer advertising Up is not a valid advance; we stay Down.
    h.listener_tx
        .send(peer_packet(BfdPeerState::Up))
        .await
        .unwrap();
    wait_for_condition(Duration::from_secs(5), || {
        h.counters.control_packets_received.load(Ordering::Relaxed) == 1
    })
    .await
    .unwrap();

    assert_eq!(*h.state_rx.borrow(), BfdPeerState::Down);
    assert_eq!(h.counters.transition_to_init.load(Ordering::Relaxed), 0);
    assert_eq!(h.counters.transition_to_up.load(Ordering::Relaxed), 0);
    assert_eq!(h.counters.transition_to_down.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn recv_timeout_drives_session_down() {
    // ~1.5s detection time (500ms * 3): long enough not to fire during the
    // sub-100ms bring-up, short enough to fire well within the 5s wait below.
    let h = spawn_driver(Duration::from_millis(500));
    bring_to_up(&h).await;

    // Stop sending; the driver's recv deadline should elapse and transition
    // the session back to Down.
    wait_for_state(&h, BfdPeerState::Down).await;
    assert!(h.counters.timeout_expired.load(Ordering::Relaxed) >= 1);
    assert!(h.counters.transition_to_down.load(Ordering::Relaxed) >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn poll_packet_elicits_final_response_on_egress() {
    let mut h = spawn_driver(Duration::from_secs(3600));

    let mut pkt = peer_packet(BfdPeerState::Down);
    pkt.set_poll();
    h.listener_tx.send(pkt).await.unwrap();

    // The driver should flush a Final response. Any startup packet has no Final
    // bit, so drain the egress channel until we see one (or time out).
    let saw_final = timeout(Duration::from_secs(5), async {
        loop {
            let bytes =
                h.egress_rx.recv().await.expect("egress channel closed");
            let pkt =
                Control::from_bytes(&bytes).expect("valid control packet");
            if pkt.r#final() {
                return;
            }
        }
    })
    .await;
    assert!(saw_final.is_ok(), "no Final response observed on egress");
}
