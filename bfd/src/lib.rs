// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use mg_common::thread::ManagedThread;
use num_enum::TryFromPrimitive;
use rdb::SessionMode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{Logger, warn};
use sm::StateMachine;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

pub mod bidi;
pub mod log;
pub mod packet;
mod sm;
mod util;

pub const COMPONENT_BFD: &str = "bfd";
pub const MOD_DAEMON: &str = "daemon";
pub const MOD_SM: &str = "state_machine";

pub const UNIT_PEER: &str = "peer";

pub const DEFAULT_BFD_TTL: u32 = 255;

/// A type alias for a bidirectional endpoint transporting BFD control messages
/// and target IP addresses.
pub type BfdEndpoint = bidi::Endpoint<(IpAddr, packet::Control)>;

/// A `Daemon` is a collection of BFD sessions.
pub struct Daemon {
    /// Sessions keyed by peer IP address.
    pub sessions: HashMap<IpAddr, Session>,

    log: Logger,
}

impl Daemon {
    /// Create a new Daemon with no sessions.
    pub fn new(log: Logger) -> Self {
        Self {
            sessions: HashMap::new(),
            log,
        }
    }

    /// Add a peer session to the daemon.
    /// Peer sessions are started immediately when added.
    pub fn add_peer(
        &mut self,
        peer: IpAddr,
        rq: AddPeerRequest,
    ) -> Result<(), AddPeerError> {
        if self.sessions.contains_key(&peer) {
            warn!(self.log, "attempt to add peer that already exists";
                "component" => COMPONENT_BFD,
                "module" => MOD_DAEMON,
                "unit" => UNIT_PEER,
                "peer" => format!("{peer}")
            );
            return Err(AddPeerError::PeerExists(peer));
        }
        self.sessions
            .insert(peer, Session::new(peer, rq, self.log.clone())?);
        Ok(())
    }

    /// Remove a peer from the daemon. The peer will be immediately shut down.
    pub fn remove_peer(&mut self, addr: IpAddr) {
        self.sessions.remove(&addr);
    }

    /// Get the state for a peer identified by its IP address.
    pub fn peer_state(&self, addr: IpAddr) -> Option<BfdPeerState> {
        self.sessions.get(&addr).map(|s| s.sm.current())
    }
}

#[derive(Default)]
pub struct SessionCounters {
    pub control_packets_sent: AtomicU64,
    pub control_packet_send_failures: AtomicU64,
    pub control_packets_received: AtomicU64,
    pub admin_down_status_received: AtomicU64,
    pub down_status_received: AtomicU64,
    pub init_status_received: AtomicU64,
    pub up_status_received: AtomicU64,
    pub unknown_status_received: AtomicU64,
    pub transition_to_init: AtomicU64,
    pub transition_to_down: AtomicU64,
    pub transition_to_up: AtomicU64,
    pub timeout_expired: AtomicU64,
    pub message_receive_error: AtomicU64,
    pub unexpected_message: AtomicU64,
}

/// Parameters for adding a new BFD peer session.
pub struct AddPeerRequest {
    pub required_rx: Duration,
    pub detection_multiplier: u8,
    pub mode: SessionMode,
    pub endpoint: BfdEndpoint,
    pub egress_thread: Option<Arc<ManagedThread>>,
    pub db: rdb::Db,
}

/// A session holds a BFD state machine for a particular peer.
pub struct Session {
    pub sm: StateMachine,
    pub mode: SessionMode,
    pub counters: Arc<SessionCounters>,
    /// Managed egress thread for UDP packet transmission. Stored here to
    /// ensure automatic cleanup on drop — the ManagedThread's Drop impl
    /// will signal shutdown and join the thread. None in test contexts
    /// where egress is handled differently.
    _egress_thread: Option<Arc<ManagedThread>>,
}

impl Session {
    /// Create a new session and start running the underlying BFD state machine
    /// immediately.
    fn new(addr: IpAddr, rq: AddPeerRequest, log: Logger) -> Result<Self> {
        let counters = Arc::new(SessionCounters::default());
        let mut sm = StateMachine::new(
            addr,
            rq.required_rx,
            rq.detection_multiplier,
            counters.clone(),
            log,
        );
        sm.run(rq.endpoint, rq.db)?;
        Ok(Session {
            sm,
            mode: rq.mode,
            counters,
            _egress_thread: rq.egress_thread,
        })
    }
}

/// Information about a BFD peer.
#[derive(Clone, Copy)]
pub struct PeerInfo {
    /// The interval at which the peer would _like_ to receive BFD control
    /// packets.
    pub desired_min_tx: Duration,

    /// This is the minimum interval between received BFD Control packets that
    /// this system is capable of supporting.
    pub required_min_rx: Duration,

    /// A unique identifer for the peer. This structure is used to keep track
    /// of remote peer information as well as our own. The remote peer
    /// generates their own discriminator. When a peer state machine is first
    /// started, we generate our discriminator with
    /// `PeerInfo::with_random_discriminator`
    pub discriminator: u32,

    /// Whether or not the peer is requesting demand mode. This means
    /// unsolicited BFD control packets will not be sent. The only control
    /// packets sent will be in response to control packets received with the
    /// poll flag set.
    pub demand_mode: bool,

    /// When multiplied against required_min_rx, defines the detection threshold
    /// connectivity status.
    pub detection_multiplier: u8,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            // Try to pick a sane default to start with. One second seems
            // prudent.
            desired_min_tx: Duration::from_secs(1),
            required_min_rx: Duration::from_secs(1),
            discriminator: 0,
            demand_mode: false,
            // Three seems to be a common choice for other implementations.
            // Without intuition for or against this default, follow suit.
            detection_multiplier: 3,
        }
    }
}

impl PeerInfo {
    /// Initialize a peer info object with a random discriminator.
    fn with_random_discriminator(
        required_min_rx: Duration,
        detection_multiplier: u8,
    ) -> Self {
        Self {
            required_min_rx,
            detection_multiplier,
            discriminator: rand::random(),
            ..Default::default()
        }
    }
}

/// The possible peer states. See the `State` trait implementations `Down`,
/// `Init`, and `Up` for detailed semantics. Data representation is u8 as
/// this enum is used as a part of the BFD wire protocol.
#[derive(
    Default,
    PartialEq,
    Debug,
    Copy,
    Clone,
    TryFromPrimitive,
    JsonSchema,
    Serialize,
    Deserialize,
)]
#[repr(u8)]
pub enum BfdPeerState {
    /// A stable down state. Non-responsive to incoming messages.
    AdminDown = 0,

    /// The initial state.
    #[default]
    Down = 1,

    /// The peer has detected a remote peer in the down state.
    Init = 2,

    /// The peer has detected a remote peer in the up or init state while in the
    /// init state.
    Up = 3,
}

pub struct Admin {}

#[derive(Debug, thiserror::Error)]
pub enum AddPeerError {
    #[error("BFD peer {0} already exists")]
    PeerExists(IpAddr),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod test {
    use super::*;
    use mg_common::eprintln_nopipe;
    use pretty_assertions::assert_eq;
    use slog::Drain;
    use std::net::IpAddr;
    use std::sync::mpsc::Sender;
    use std::thread::{sleep, spawn};

    struct Network {
        endpoints: Option<HashMap<IpAddr, BfdEndpoint>>,
    }

    impl Default for Network {
        fn default() -> Self {
            Self {
                endpoints: Some(HashMap::new()),
            }
        }
    }

    impl Network {
        fn register(&mut self, addr: IpAddr, endpoint: BfdEndpoint) {
            self.endpoints
                .as_mut()
                .expect("network already running, cannot register endpoint")
                .insert(addr, endpoint);
        }

        fn run(&mut self) {
            let mut endpoints: Vec<(IpAddr, BfdEndpoint)> = self
                .endpoints
                .take()
                .expect("network running")
                .into_iter()
                .collect();

            // Construct a map of senders handlers to forward to
            let egress: HashMap<IpAddr, Sender<(IpAddr, packet::Control)>> =
                endpoints.iter().map(|(a, e)| (*a, e.tx.clone())).collect();

            while let Some((addr, ep)) = endpoints.pop() {
                let egress = egress
                    .clone()
                    .into_iter()
                    .filter(|(a, _)| *a != addr)
                    .collect();
                Self::run_message_handler(ep, egress);
            }
        }

        fn run_message_handler(
            ep: BfdEndpoint,
            egress: HashMap<IpAddr, Sender<(IpAddr, packet::Control)>>,
        ) {
            spawn(move || {
                loop {
                    match ep.rx.recv() {
                        Ok((addr, msg)) => match egress.get(&addr) {
                            Some(tx) => {
                                tx.send((addr, msg)).unwrap();
                            }
                            None => {
                                eprintln_nopipe!("no egress for {}", addr);
                            }
                        },
                        Err(e) => {
                            eprintln_nopipe!("recv: {}", e);
                        }
                    }
                }
            });
        }
    }

    fn ip(addr: &str) -> IpAddr {
        addr.parse().unwrap()
    }

    #[test]
    fn test_new_daemon() -> anyhow::Result<()> {
        let log = test_logger();
        let db = rdb::test::get_test_db("bfd_new_daemon", log.clone()).unwrap();

        let mut daemon = Daemon::new(log);
        assert_eq!(daemon.sessions.len(), 0);

        // Add an IPv4 peer.
        let (a, _b) = bidi::channel();
        let v4_addr = ip("203.0.113.10");
        daemon.add_peer(
            v4_addr,
            AddPeerRequest {
                required_rx: Duration::from_secs(5),
                detection_multiplier: 3,
                mode: SessionMode::MultiHop,
                endpoint: a,
                egress_thread: None,
                db: db.db().clone(),
            },
        )?;
        assert_eq!(daemon.peer_state(v4_addr), Some(BfdPeerState::Down));

        // Add an IPv6 peer to the same daemon.
        let (a, _b) = bidi::channel();
        let v6_addr = ip("2001:db8::10");
        daemon.add_peer(
            v6_addr,
            AddPeerRequest {
                required_rx: Duration::from_secs(5),
                detection_multiplier: 3,
                mode: SessionMode::MultiHop,
                endpoint: a,
                egress_thread: None,
                db: db.db().clone(),
            },
        )?;
        assert_eq!(daemon.peer_state(v6_addr), Some(BfdPeerState::Down));

        // Both peers coexist.
        assert_eq!(daemon.sessions.len(), 2);

        Ok(())
    }

    #[test]
    fn test_protocol_basics() -> anyhow::Result<()> {
        let log = test_logger();
        let db =
            rdb::test::get_test_db("bfd_protocol_basics", log.clone()).unwrap();

        let mut net = Network::default();

        // IPv4 peer pair.
        let v4_addr1 = ip("203.0.113.10");
        let v4_addr2 = ip("203.0.113.20");

        // IPv6 peer pair.
        let v6_addr1 = ip("2001:db8::10");
        let v6_addr2 = ip("2001:db8::20");

        // Daemon 1 peers with both v4 and v6 counterparts.
        let mut d1 = Daemon::new(test_logger());
        let (a, b) = bidi::channel();
        d1.add_peer(
            v4_addr1,
            AddPeerRequest {
                required_rx: Duration::from_secs(5),
                detection_multiplier: 3,
                mode: SessionMode::MultiHop,
                endpoint: a,
                egress_thread: None,
                db: db.db().clone(),
            },
        )?;
        net.register(v4_addr2, b);

        let (a, b) = bidi::channel();
        d1.add_peer(
            v6_addr1,
            AddPeerRequest {
                required_rx: Duration::from_secs(5),
                detection_multiplier: 3,
                mode: SessionMode::MultiHop,
                endpoint: a,
                egress_thread: None,
                db: db.db().clone(),
            },
        )?;
        net.register(v6_addr2, b);

        // Daemon 2 peers with both v4 and v6 counterparts.
        let mut d2 = Daemon::new(test_logger());
        let (a, b) = bidi::channel();
        d2.add_peer(
            v4_addr2,
            AddPeerRequest {
                required_rx: Duration::from_secs(5),
                detection_multiplier: 3,
                mode: SessionMode::MultiHop,
                endpoint: a,
                egress_thread: None,
                db: db.db().clone(),
            },
        )?;
        net.register(v4_addr1, b);

        let (a, b) = bidi::channel();
        d2.add_peer(
            v6_addr2,
            AddPeerRequest {
                required_rx: Duration::from_secs(5),
                detection_multiplier: 3,
                mode: SessionMode::MultiHop,
                endpoint: a,
                egress_thread: None,
                db: db.db().clone(),
            },
        )?;
        net.register(v6_addr1, b);

        net.run();

        sleep(Duration::from_secs(10));

        // All four sessions should reach Up.
        assert_eq!(d1.peer_state(v4_addr1), Some(BfdPeerState::Up),);
        assert_eq!(d1.peer_state(v6_addr1), Some(BfdPeerState::Up),);
        assert_eq!(d2.peer_state(v4_addr2), Some(BfdPeerState::Up),);
        assert_eq!(d2.peer_state(v6_addr2), Some(BfdPeerState::Up),);

        Ok(())
    }

    fn test_logger() -> Logger {
        let drain = slog_bunyan::new(std::io::stdout()).build().fuse();
        let drain = slog_async::Async::new(drain)
            .chan_size(0x8000)
            .build()
            .fuse();
        slog::Logger::root(drain, slog::o!())
    }
}
