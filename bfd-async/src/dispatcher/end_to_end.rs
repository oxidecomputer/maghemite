// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! End-to-end tests that wire two complete BFD sessions together over real
//! loopback UDP sockets, confirming they negotiate `Up` and tear down to `Down`
//! when a peer disappears.
//!
//! To avoid any dependency on binding the real BFD ports (3784 / 4784) -- which
//! may be in use or unavailable -- each daemon's listener adopts a socket we
//! bind ourselves on `127.0.0.1:0` via a custom `Dispatcher` backend. That's
//! also why this test lives here organizationally: we need access to the
//! private backend bits that aren't exposed more widely.

use super::Dispatcher;
use super::ListenerBackend;
use super::ListenerTask;
use super::SharedSessions;
use crate::AddPeerError;
use crate::AddPeerRequest;
use crate::Daemon;
use crate::wait_for_condition;
use bfd::DEFAULT_DETECT_MULTIPLIER;
use mg_api_types::bfd::BfdPeerState;
use mg_api_types::bfd::SessionMode;
use slog::Logger;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Test timing: a `required_rx` of 100ms with a detection multiplier of 3 gives
/// a 300ms detection time, which should be slow enough to avoid flakiness in CI
/// but fast enough that the test doesn't take forever.
const REQUIRED_RX_MICROS: u64 = Duration::from_millis(100).as_micros() as u64;
const DETECTION_MULT: NonZeroU8 = DEFAULT_DETECT_MULTIPLIER;

fn test_logger() -> Logger {
    Logger::root(slog::Discard, slog::o!())
}

/// State of the single session owned by a test daemon.
fn only_state(daemon: &Daemon) -> BfdPeerState {
    daemon
        .sessions_iter()
        .next()
        .expect("daemon has exactly one session")
        .1
        .state()
}

// Our custom backend: we start with a single socket, and we hand it out the
// first time `Dispatcher` asks us to spawn a task. Any subsequent spawn
// attempts will panic.
struct PreBoundSocketBackend {
    socket: Mutex<Option<UdpSocket>>,
}

impl PreBoundSocketBackend {
    fn new(socket: UdpSocket) -> Self {
        Self {
            socket: Mutex::new(Some(socket)),
        }
    }
}

impl ListenerBackend for PreBoundSocketBackend {
    fn spawn(
        &self,
        _listen_addr: SocketAddr,
        sessions: SharedSessions,
        log: Logger,
    ) -> Result<JoinHandle<()>, AddPeerError> {
        let socket = self
            .socket
            .lock()
            .unwrap()
            .take()
            .expect("PreBoundSocketBackend::spawn called more than once");
        let listen_task = ListenerTask::new(socket, sessions, log);
        Ok(tokio::spawn(listen_task.run()))
    }
}

/// Build a `Daemon` whose listener is bound to an ephemeral loopback port, and
/// return the daemon, that listening address, and the backing test db (which
/// must be kept alive for the duration of the test).
async fn build_daemon(
    test_name: &str,
) -> (Daemon, SocketAddr, rdb::test::TestDb) {
    let log = test_logger();
    let socket = UdpSocket::bind((LOCALHOST, 0))
        .await
        .expect("bind loopback socket");
    let listen_addr = socket.local_addr().expect("socket has local addr");
    let db =
        rdb::test::get_test_db(test_name, log.clone()).expect("create test db");
    let daemon = Daemon::with_dispatcher(
        Dispatcher::with_backend(Arc::new(PreBoundSocketBackend::new(socket))),
        log,
    );
    (daemon, listen_addr, db)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_sessions_converge_then_peer_loss_drives_down() {
    let (mut daemon_a, addr_a, db_a) = build_daemon("bfd_async_e2e_a").await;
    let (mut daemon_b, addr_b, db_b) = build_daemon("bfd_async_e2e_b").await;

    // A's egress targets B's listener and vice versa.
    daemon_a
        .add_peer(
            db_a.db().clone(),
            AddPeerRequest {
                remote_addr: addr_b,
                listen_addr: addr_a,
                required_rx_micros: REQUIRED_RX_MICROS,
                detection_threshold: DETECTION_MULT,
                mode: SessionMode::MultiHop,
            },
        )
        .expect("add peer to daemon a");
    daemon_b
        .add_peer(
            db_b.db().clone(),
            AddPeerRequest {
                remote_addr: addr_a,
                listen_addr: addr_b,
                required_rx_micros: REQUIRED_RX_MICROS,
                detection_threshold: DETECTION_MULT,
                mode: SessionMode::MultiHop,
            },
        )
        .expect("add peer to daemon b");

    // Both sessions should handshake Down -> Init -> Up and stay there.
    wait_for_condition(Duration::from_secs(30), || {
        only_state(&daemon_a) == BfdPeerState::Up
            && only_state(&daemon_b) == BfdPeerState::Up
    })
    .await
    .expect("both sessions reach Up");

    // Drop B's peer: this aborts B's session (so it stops sending) and shuts
    // down B's listener socket.
    let handle = daemon_b
        .remove_peer(addr_a.ip())
        .expect("removing the only peer yields a shutdown handle");
    handle.shutdown().await;

    // With B silent, A's recv deadline expires and it transitions to Down.
    wait_for_condition(Duration::from_secs(10), || {
        only_state(&daemon_a) == BfdPeerState::Down
    })
    .await
    .expect("session a goes Down after peer loss");

    // Keep the dbs alive until the end so their tasks don't see a vanished db.
    drop((db_a, db_b));
}
