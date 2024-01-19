// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use num_enum::TryFromPrimitive;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::Logger;
use sm::StateMachine;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

pub mod bidi;
pub mod packet;
mod sm;
mod util;

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

    /// Add a peer session to the deamon. Peer sessions are started immediately
    /// when added.
    pub fn add_peer(
        &mut self,
        addr: IpAddr,
        required_rx: Duration,
        detection_multiplier: u8,
        endpoint: bidi::Endpoint<(IpAddr, packet::Control)>,
        db: rdb::Db,
    ) {
        if self.sessions.contains_key(&addr) {
            return;
        }
        self.sessions.insert(
            addr,
            Session::new(
                addr,
                endpoint,
                required_rx,
                detection_multiplier,
                db,
                self.log.clone(),
            ),
        );
    }

    /// Remove a peer from the daemon. The peer will be immediately shut down.
    pub fn remove_peer(&mut self, addr: IpAddr) {
        self.sessions.remove(&addr);
    }

    /// Get the state for a peer identified by its IP address.
    pub fn peer_state(&self, addr: IpAddr) -> Option<PeerState> {
        self.sessions.get(&addr).map(|s| s.sm.current())
    }
}

/// A session holds a BFD state machine for a particular peer.
pub struct Session {
    pub sm: StateMachine,
}

impl Session {
    /// Create a new session and start running the underlying BFD state machine
    /// immediately.
    fn new(
        addr: IpAddr,
        ep: bidi::Endpoint<(IpAddr, packet::Control)>,
        required_rx: Duration,
        detection_multiplier: u8,
        db: rdb::Db,
        log: Logger,
    ) -> Self {
        let mut sm =
            StateMachine::new(addr, required_rx, detection_multiplier, log);
        sm.run(ep, db);
        Session { sm }
    }
}

/// Information about a BFD peer.
#[derive(Clone, Copy)]
pub struct PeerInfo {
    /// The interval at which the peer would _like_ to receive BFD control
    /// packets.
    pub desired_min_tx: Duration,

    /// This is the minimum interval, in microseconds, between received
    /// BFD Control packets that this system is capable of supporting,
    pub required_min_rx: Duration,

    /// A unique identifer for the peer.
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
/// `Init`, and `Up` for detailed semantics.
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
pub enum PeerState {
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

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use slog::Drain;
    use std::net::IpAddr;
    use std::sync::mpsc::Sender;
    use std::thread::{sleep, spawn};

    struct Network {
        endpoints:
            Option<HashMap<IpAddr, bidi::Endpoint<(IpAddr, packet::Control)>>>,
    }

    impl Default for Network {
        fn default() -> Self {
            Self {
                endpoints: Some(HashMap::new()),
            }
        }
    }

    impl Network {
        fn register(
            &mut self,
            addr: IpAddr,
            endpoint: bidi::Endpoint<(IpAddr, packet::Control)>,
        ) {
            self.endpoints
                .as_mut()
                .expect("network already running, cannot register endpoint")
                .insert(addr, endpoint);
        }

        fn run(&mut self) {
            let mut endpoints: Vec<(
                IpAddr,
                bidi::Endpoint<(IpAddr, packet::Control)>,
            )> = self
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
            ep: bidi::Endpoint<(IpAddr, packet::Control)>,
            egress: HashMap<IpAddr, Sender<(IpAddr, packet::Control)>>,
        ) {
            spawn(move || loop {
                match ep.rx.recv() {
                    Ok((addr, msg)) => match egress.get(&addr) {
                        Some(tx) => {
                            tx.send((addr, msg)).unwrap();
                        }
                        None => {
                            eprintln!("no egress for {}", addr);
                        }
                    },
                    Err(e) => {
                        eprintln!("recv: {}", e);
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
        let db = rdb::Db::new("/tmp/bfd_new_daemon.db", test_logger()).unwrap();

        let mut daemon = Daemon::new(test_logger());
        assert_eq!(daemon.sessions.len(), 0);

        let (a, _b) = bidi::channel();
        let p1_addr = ip("203.0.113.10");
        daemon.add_peer(p1_addr, Duration::from_secs(5), 3, a, db);
        assert_eq!(daemon.peer_state(p1_addr), Some(PeerState::Down));

        Ok(())
    }

    #[test]
    fn test_protocol_basics() -> anyhow::Result<()> {
        let db = rdb::Db::new("/tmp/bfd_new_daemon.db", test_logger()).unwrap();

        let mut net = Network::default();

        let addr1 = ip("203.0.113.10");
        let addr2 = ip("203.0.113.20");

        let mut d1 = Daemon::new(test_logger());
        let (a, b) = bidi::channel();
        d1.add_peer(addr1, Duration::from_secs(5), 3, a, db.clone());
        net.register(addr2, b);

        let mut d2 = Daemon::new(test_logger());
        let (a, b) = bidi::channel();
        d2.add_peer(addr2, Duration::from_secs(5), 3, a, db);
        net.register(addr1, b);

        net.run();

        sleep(Duration::from_secs(10));

        assert_eq!(d1.peer_state(addr1), Some(PeerState::Up));
        assert_eq!(d2.peer_state(addr2), Some(PeerState::Up));

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
