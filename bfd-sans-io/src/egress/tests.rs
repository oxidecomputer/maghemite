// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use slog::Discard;
use slog::o;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn test_logger() -> Logger {
    Logger::root(Discard, o!())
}

/// Spawn an egress task sending to `remote`, returning its channel sender,
/// counters, and join handle.
fn spawn_egress(
    remote: SocketAddr,
    mode: SessionMode,
    egress_src_port: Arc<SingleHopEgressSrcPort>,
) -> (
    mpsc::Sender<Vec<u8>>,
    Arc<SessionCounters>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel(2);
    let counters = Arc::new(SessionCounters::default());
    let task = EgressTask::new(
        rx,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote,
        mode,
        egress_src_port,
        Arc::clone(&counters),
        test_logger(),
    );
    let handle = tokio::spawn(task.run());
    (tx, counters, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_bytes_to_peer() {
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    let (tx, counters, _handle) = spawn_egress(
        peer_addr,
        SessionMode::MultiHop,
        Arc::new(SingleHopEgressSrcPort::new()),
    );

    tx.send(b"hello bfd".to_vec()).await.unwrap();

    let mut buf = [0u8; 64];
    let (n, _src) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("timed out waiting for egress datagram")
        .unwrap();
    assert_eq!(&buf[..n], b"hello bfd");
    assert_eq!(counters.control_packets_sent.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn singlehop_mode_binds_ports_in_expected_range() {
    // Bind two peers, then spawn two egress tasks. Send a message to each so
    // our peer can detect the port on which the egress tasks were bound; both
    // should be in the range [49152, ..]. We generally expect to get exactly
    // 49152 and 49153, but we can't assert that: if one or both of those ports
    // are already in use on whatever system this test is running, we'll search
    // beyond that.
    let peer1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer1_addr = peer1.local_addr().unwrap();
    let peer2_addr = peer2.local_addr().unwrap();

    let egress_src_port = Arc::new(SingleHopEgressSrcPort::new());
    let (tx1, counters1, _handle) = spawn_egress(
        peer1_addr,
        SessionMode::SingleHop,
        Arc::clone(&egress_src_port),
    );
    let (tx2, counters2, _handle) = spawn_egress(
        peer2_addr,
        SessionMode::SingleHop,
        Arc::clone(&egress_src_port),
    );

    // Helper function to detect the src port bound by an egress task.
    //
    // This is to reduce test flakiness on a system where many of the ports at
    // the beginning of the valid singlehop egress range (starting at 49152) are
    // already in use by other processes, and we may need to search multiple
    // times through the space to find a free port.
    async fn detect_egress_src_port(
        tx: mpsc::Sender<Vec<u8>>,
        counters: Arc<SessionCounters>,
        peer: UdpSocket,
    ) -> u16 {
        let mut prev_send_failures = 0;
        let mut buf = [0; 128];

        'try_send: loop {
            tx.send(b"hello".to_vec()).await.unwrap();

            // Periodically check for either:
            //
            // 1. the peer received a packet
            // 2. the egress task incremented `control_packets_send_failures`,
            //    indicating it couldn't find a free port to bind
            loop {
                tokio::select! {
                    result = peer.recv_from(&mut buf) => {
                        let (n, src) = result.unwrap();
                        assert_eq!(&buf[..n], b"hello");
                        return src.port();
                    }
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                        let nfailures = counters
                            .control_packet_send_failures
                            .load(Ordering::Relaxed);
                        if nfailures > prev_send_failures {
                            prev_send_failures = nfailures;
                            continue 'try_send;
                        }
                    }
                }
            }
        }
    }

    let srcport1 = tokio::time::timeout(
        Duration::from_secs(10),
        detect_egress_src_port(tx1, counters1, peer1),
    )
    .await
    .expect("found src port for peer 1");
    let srcport2 = tokio::time::timeout(
        Duration::from_secs(10),
        detect_egress_src_port(tx2, counters2, peer2),
    )
    .await
    .expect("found src port for peer 2");

    assert_ne!(srcport1, srcport2);
    assert!(
        srcport1 >= SingleHopEgressSrcPort::SOURCE_PORT_BEGIN,
        "unexpected singlehop src port {srcport1}"
    );
    assert!(
        srcport2 >= SingleHopEgressSrcPort::SOURCE_PORT_BEGIN,
        "unexpected singlehop src port {srcport2}"
    );

}

#[tokio::test(flavor = "multi_thread")]
async fn exits_when_channel_closed() {
    let (tx, _counters, handle) = spawn_egress(
        "127.0.0.1:1".parse().unwrap(),
        SessionMode::MultiHop,
        Arc::new(SingleHopEgressSrcPort::new()),
    );
    drop(tx);
    timeout(Duration::from_secs(5), handle)
        .await
        .expect("egress task did not exit after channel close")
        .expect("egress task panicked");
}
