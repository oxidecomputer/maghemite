// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wire-level tests for `Dispatcher`/`Listener`, exercising the real
//! [`super::TokioUdpBinder`] backend over loopback UDP sockets.

use super::Dispatcher;
use super::ListenerBackend;
use super::ListenerTask;
use bfd::SessionCounters;
use bfd::packet::Control;
use slog::Discard;
use slog::Logger;
use slog::o;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const LISTEN_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
const PEER_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn test_logger() -> Logger {
    Logger::root(Discard, o!())
}

/// All these tests bind to the listening address `127.0.0.1:0`, but we need to
/// know the actual bound port in order to send messages to it. We use a custom
/// `ListenerBackend` here that remembers that port, but then forwards the
/// socket back to the real `ListenerTask` just like the real `TokioUdpBinder`
/// backend does.
#[derive(Debug, Default)]
struct TestBackend {
    bound_address: Mutex<Option<SocketAddr>>,
    listener_task_was_dropped: Arc<AtomicBool>,
}

impl TestBackend {
    fn as_backend(self: &Arc<Self>) -> Arc<dyn ListenerBackend> {
        Arc::clone(self) as Arc<dyn ListenerBackend>
    }

    fn expect_bound_address(&self) -> SocketAddr {
        self.bound_address
            .lock()
            .unwrap()
            .expect("socket has been bound")
    }

    fn was_listener_task_dropped(&self) -> bool {
        self.listener_task_was_dropped.load(Ordering::Relaxed)
    }
}

impl ListenerBackend for TestBackend {
    fn spawn(
        &self,
        listen_addr: SocketAddr,
        sessions: super::SharedSessions,
        log: Logger,
    ) -> Result<tokio::task::JoinHandle<()>, crate::AddPeerError> {
        assert_eq!(listen_addr, LISTEN_ADDR);

        let mut bound_address = self.bound_address.lock().unwrap();
        assert!(
            bound_address.is_none(),
            "TestBackend can only spawn one listening socket"
        );

        let socket =
            std::net::UdpSocket::bind(listen_addr).expect("bound socket");
        *bound_address =
            Some(socket.local_addr().expect("socket has local addr"));

        socket.set_nonblocking(true).expect("set nonblocking");
        let socket = UdpSocket::from_std(socket).expect("adopted socket");
        let listen_task = ListenerTask::new(socket, sessions, log);

        let listen_task = tokio::spawn({
            // Construct a drop guard that sets our `listener_task_was_dropped`
            // flag whenever the guard is dropped. Tests can use this to check
            // whether the spawned task was actually shut down.
            struct SetOnDrop(Arc<AtomicBool>);
            impl Drop for SetOnDrop {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let guard = SetOnDrop(Arc::clone(&self.listener_task_was_dropped));
            async move {
                let _guard = guard;
                listen_task.run().await;
            }
        });

        Ok(listen_task)
    }
}

/// A client socket bound to loopback; packets it sends have a source IP of
/// `127.0.0.1`.
async fn client() -> UdpSocket {
    UdpSocket::bind(LISTEN_ADDR).await.unwrap()
}

/// A valid control packet whose `my_discriminator` we can use to identify it on
/// the receiving end.
fn packet(discriminator: u32) -> Control {
    Control {
        my_discriminator: discriminator,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn delivers_packet_from_registered_peer() {
    let log = test_logger();
    let backend = Arc::new(TestBackend::default());
    let mut dispatcher = Dispatcher::with_backend(backend.as_backend());

    let mut rx = dispatcher
        .ensure(LISTEN_ADDR, PEER_ADDR, Arc::default(), &log)
        .unwrap();

    let pkt = packet(0xABCD);
    client()
        .await
        .send_to(&pkt.to_bytes(), backend.expect_bound_address())
        .await
        .unwrap();

    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for packet")
        .expect("channel closed");
    assert_eq!(got.to_bytes(), pkt.to_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn drops_packet_from_unregistered_peer() {
    let log = test_logger();
    let backend = Arc::new(TestBackend::default());
    let mut dispatcher = Dispatcher::with_backend(backend.as_backend());

    // Register a peer that is *not* the loopback source address our client
    // sends from, so the listener sees a mismatched source IP.
    let peer: IpAddr = "192.0.2.1".parse().unwrap();

    let mut rx = dispatcher
        .ensure(LISTEN_ADDR, peer, Arc::default(), &log)
        .unwrap();

    client()
        .await
        .send_to(&packet(1).to_bytes(), backend.expect_bound_address())
        .await
        .unwrap();

    // Nothing should be delivered: the source IP (127.0.0.1) isn't registered.
    let res = timeout(Duration::from_millis(300), rx.recv()).await;
    assert!(res.is_err(), "expected no delivery, got {res:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn drops_malformed_packet_but_task_survives() {
    let log = test_logger();
    let backend = Arc::new(TestBackend::default());
    let counters = Arc::new(SessionCounters::default());
    let mut dispatcher = Dispatcher::with_backend(backend.as_backend());
    let mut rx = dispatcher
        .ensure(LISTEN_ADDR, PEER_ADDR, Arc::clone(&counters), &log)
        .unwrap();

    let addr = backend.expect_bound_address();
    let c = client().await;
    // Too short to be a valid BFD control packet (minimum is 24 bytes).
    c.send_to(&[0xff, 0xff], addr).await.unwrap();
    // A subsequent valid packet must still be delivered, proving the listener
    // task didn't die on the parse error.
    c.send_to(&packet(0x1234).to_bytes(), addr).await.unwrap();

    let got = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out")
        .expect("channel closed");
    assert_eq!(got.my_discriminator, 0x1234);

    // We should also have bumped the counter for the malformed packet.
    let nerror = counters.unexpected_message.load(Ordering::Relaxed);
    assert_eq!(nerror, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn bounded_channel_drops_excess_packets() {
    let log = test_logger();
    let backend = Arc::new(TestBackend::default());
    let mut dispatcher = Dispatcher::with_backend(backend.as_backend());
    let counters = Arc::new(SessionCounters::default());
    let mut rx = dispatcher
        .ensure(LISTEN_ADDR, PEER_ADDR, Arc::clone(&counters), &log)
        .unwrap();
    let addr = backend.expect_bound_address();

    let c = client().await;
    let bytes = packet(0).to_bytes();
    // Flood the listener without draining the channel.
    for _ in 0..50 {
        c.send_to(&bytes, addr).await.unwrap();
    }

    // Give the listener task time to drain the socket into the channel.
    let start_waiting = Instant::now();
    loop {
        if rx.len() == rx.max_capacity() {
            break;
        }
        if start_waiting.elapsed() > Duration::from_secs(5) {
            panic!("packet flood didn't fill channel after 5 seconds");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // We should have records of dropped packets.
    let nerror = counters.message_receive_error.load(Ordering::Relaxed);
    assert!(nerror > 0, "no errors recorded");

    // The channel buffers at most its capacity (8); the rest is dropped. (UDP
    // itself may also drop, so we only assert the upper bound and liveness.)
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert!(count >= 8, "expected a full channel worth of packets");

    // The task is still alive: with room in the channel, a fresh packet flows.
    c.send_to(&bytes, addr).await.unwrap();
    let got = timeout(Duration::from_secs(5), rx.recv()).await;
    assert!(matches!(got, Ok(Some(_))), "task did not survive: {got:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_task_to_be_dropped() {
    let log = test_logger();
    let backend = Arc::new(TestBackend::default());
    let mut dispatcher = Dispatcher::with_backend(backend.as_backend());
    let _rx = dispatcher
        .ensure(LISTEN_ADDR, PEER_ADDR, Arc::default(), &log)
        .unwrap();

    let handle = dispatcher
        .remove(PEER_ADDR)
        .expect("removing last peer yields a handle");

    // Awaiting shutdown guarantees the task was aborted and dropped.
    handle.shutdown().await;

    assert!(backend.was_listener_task_dropped());
}

#[tokio::test(flavor = "multi_thread")]
async fn rx_closed_after_last_peer_removed() {
    let log = test_logger();
    let backend = Arc::new(TestBackend::default());
    let mut dispatcher = Dispatcher::with_backend(backend.as_backend());
    let mut rx = dispatcher
        .ensure(LISTEN_ADDR, PEER_ADDR, Arc::default(), &log)
        .unwrap();

    let handle = dispatcher.remove(PEER_ADDR).expect("handle");
    handle.shutdown().await;

    // The only sender lived in the listener's session map; once the listener
    // and its task are gone, the channel is closed.
    let got = timeout(Duration::from_secs(5), rx.recv()).await;
    assert!(
        matches!(got, Ok(None)),
        "expected closed channel, got {got:?}"
    );
}
