// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::err;
use crate::packet::Control;
use crate::{
    bidi, inf, packet, trc, util::update_peer_info, wrn, BfdPeerState, PeerInfo,
};
use anyhow::{anyhow, Result};
use slog::{warn, Logger};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;

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
    state: Arc<RwLock<Box<dyn State>>>,
    peer: IpAddr,
    required_rx: Duration,
    detection_multiplier: u8,
    kill_switch: Arc<AtomicBool>,
    log: Logger,
}

impl Drop for StateMachine {
    fn drop(&mut self) {
        self.kill_switch.store(true, Ordering::Relaxed);
    }
}

impl StateMachine {
    /// Create a new state machine, but do not start it.
    pub fn new(
        peer: IpAddr,
        required_rx: Duration,
        detection_multiplier: u8,
        log: Logger,
    ) -> Self {
        let state = Down::new(peer, log.clone());
        Self {
            state: Arc::new(RwLock::new(Box::new(state))),
            peer,
            required_rx,
            detection_multiplier,
            kill_switch: Arc::new(AtomicBool::new(false)),
            log,
        }
    }

    /// Run the state machine, transitioning from state to state based on
    /// incoming control packets. Endpoint is a channel from a connection
    /// dispatcher that sends control packets to this state machine based
    /// on peer address and BFD discriminator.
    pub fn run(
        &mut self,
        endpoint: bidi::Endpoint<(IpAddr, packet::Control)>,
        db: rdb::Db,
    ) {
        let local = PeerInfo::with_random_discriminator(
            self.required_rx,
            self.detection_multiplier,
        );
        let remote = Arc::new(Mutex::new(PeerInfo::default()));

        // Span a thread that runs the send loop for this state machine. This
        // loop is responsible for sending out unsolicited periodic control
        // packets.
        self.send_loop(endpoint.tx.clone(), local, remote.clone());

        // Spawn a thread that runs the receive loop. This loop is responsible
        // for handling packets from the connection dispatcher.
        self.recv_loop(endpoint, db, local, remote.clone());
    }

    /// Get the current state of this state machine.
    pub fn current(&self) -> BfdPeerState {
        self.state.read().unwrap().state()
    }

    /// Spawn a thread that runs the receive loop. This loop is responsible
    /// for handling packets from the connection dispatcher. This handler
    /// determines what BFD state we are in and delegates handling of the
    /// packet to that state's handler.
    fn recv_loop(
        &self,
        mut endpoint: bidi::Endpoint<(IpAddr, packet::Control)>,
        db: rdb::Db,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
    ) {
        let state = self.state.clone();
        let peer = self.peer;
        let kill_switch = self.kill_switch.clone();
        let log = self.log.clone();
        spawn(move || loop {
            let prev = state.read().unwrap().state();
            let (st, ep) = match state.read().unwrap().run(
                endpoint,
                local,
                remote.clone(),
                kill_switch.clone(),
                db.clone(),
            ) {
                Ok(result) => result,
                Err(_) => break,
            };
            *state.write().unwrap() = st;
            endpoint = ep;
            let new = state.read().unwrap().state();

            if prev != new {
                inf!(log, prev, peer; "transition -> {:?}", new);
            }
        });
    }

    /// This is a send loop for a BFD peer. It takes care of sending out
    /// unsolicited periodic control packets. Synchronization betwen this send
    /// loop and the trait implementors receive loop happens through the
    /// `remote` peer info mutex.
    fn send_loop(
        &self,
        sender: Sender<(IpAddr, packet::Control)>,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
    ) {
        let state = self.state.clone();
        let peer = self.peer;
        let stop = self.kill_switch.clone();
        let log = self.log.clone();
        // State does not change for the lifetime of the trait so it's safe to
        // just copy it out of self for sending into the spawned thread. The
        // reason this is a dynamic method at all is to get runtime polymorphic
        // behavior over `State` trait implementors.
        spawn(move || loop {
            if stop.load(Ordering::Relaxed) {
                break;
            };

            // Get what we need from peer info, holding the lock a briefly as
            // possible.
            let (_delay, demand_mode, your_discriminator) = {
                let r = remote.lock().unwrap();
                (
                    DeferredDelay(r.required_min_rx),
                    r.demand_mode,
                    r.discriminator,
                )
            };

            // Unsolicited packets are not sent in demand mode.
            //
            // TODO we could probably just park this thread on a signal waiting
            // to leave demand mode instead of continuing to iterate.
            if demand_mode {
                continue;
            }

            let mut pkt = packet::Control {
                desired_min_tx: local.desired_min_tx.as_micros() as u32,
                required_min_rx: local.required_min_rx.as_micros() as u32,
                my_discriminator: local.discriminator,
                your_discriminator,
                ..Default::default()
            };

            let st = state.read().unwrap().state();
            pkt.set_state(st);

            if let Err(e) = sender.send((peer, pkt)) {
                wrn!(log, st, peer; "send: {}", e);
            }
        });
    }

    pub fn required_rx(&self) -> Duration {
        self.required_rx
    }

    pub fn detection_multiplier(&self) -> u8 {
        self.detection_multiplier
    }
}

/// A type alias for a bidirectional endpoint transporting BFD control messages
/// and target IP addresses.
pub(crate) type BfdEndpoint = bidi::Endpoint<(IpAddr, packet::Control)>;

/// A helper object to make delayed loop implementations less error prone.
struct DeferredDelay(Duration);

impl Drop for DeferredDelay {
    /// On drop, delay for the specified duration. Use this in a loop to
    /// implement a delay loop.
    fn drop(&mut self) {
        sleep(self.0);
    }
}

pub enum RecvResult {
    MessageFrom((IpAddr, Control)),
    TransitionTo(Box<dyn State>),
}

//TODO consider using a `State` enum instead of identical structs that
//     implement a `State` trait. This could be similar to how BGP is
//     implemented or we could even look into a unified state machine
//     framework for Maghemite protocol implementations in general.
//
//     https://github.com/oxidecomputer/maghemite/issues/153

/// All BFD states must implement the state trait.
pub(crate) trait State: Sync + Send {
    /// Run the BFD state. This involves listening for messages on the provide
    /// endpoint, responding to peers accordingly and making the appropriate
    /// state transition when necessary by returning a new State implementation.
    fn run(
        &self,
        endpoint: BfdEndpoint,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
        kill_switch: Arc<AtomicBool>,
        db: rdb::Db,
    ) -> Result<(Box<dyn State>, BfdEndpoint)>;

    /// Return the `BfdPeerState` associated with the implementor of this trait.
    fn state(&self) -> BfdPeerState;

    fn peer(&self) -> IpAddr;

    /// State trait implementors should call this fuction in response to poll
    /// packets. It will send an appropriate BFD control packet in response with
    /// the final flag set.
    fn send_poll_response(
        &self,
        peer: IpAddr,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
        sender: Sender<(IpAddr, packet::Control)>,
        log: Logger,
    ) {
        let state = self.state();
        let your_discriminator = remote.lock().unwrap().discriminator;

        let mut pkt = packet::Control {
            desired_min_tx: local.desired_min_tx.as_micros() as u32,
            required_min_rx: local.required_min_rx.as_micros() as u32,
            my_discriminator: local.discriminator,
            your_discriminator,
            ..Default::default()
        };
        pkt.set_state(state);
        pkt.set_final();

        if let Err(e) = sender.send((peer, pkt)) {
            wrn!(log, state, peer; "send: {}", e);
        }
    }

    fn recv(
        &self,
        endpoint: &BfdEndpoint,
        local: PeerInfo,
        remote: &Arc<Mutex<PeerInfo>>,
        log: Logger,
    ) -> Result<RecvResult> {
        match endpoint.rx.recv_timeout(
            local.required_min_rx * local.detection_multiplier.into(),
        ) {
            Ok((addr, msg)) => {
                trc!(log, self.state(), self.peer(); "recv: {:?}", msg);

                update_peer_info(remote, &msg);

                if msg.poll() {
                    self.send_poll_response(
                        self.peer(),
                        local,
                        remote.clone(),
                        endpoint.tx.clone(),
                        log.clone(),
                    );
                }

                Ok(RecvResult::MessageFrom((addr, msg)))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                wrn!(log, self.state(), self.peer(); "timeout expired");
                let next = Down::new(self.peer(), log.clone());
                Ok(RecvResult::TransitionTo(Box::new(next)))
            }
            Err(e) => {
                err!(
                    log,
                    self.state(),
                    self.peer();
                    "recv: {}, exiting recieve loop",
                    e
                );
                Err(anyhow::anyhow!("recv channel closed"))
            }
        }
    }
}

/// The BFD down state. The following is taken verbatim from the RFC.
///
/// > Down state means that the session is down (or has just been created).
/// > A session remains in Down state until the remote system indicates
/// > that it agrees that the session is down by sending a BFD Control
/// > packet with the State field set to anything other than Up.  If that
/// > packet signals Down state, the session advances to Init state; if
/// > that packet signals Init state, the session advances to Up state.
/// > Semantically, Down state indicates that the forwarding path is
/// > unavailable, and that appropriate actions should be taken by the
/// > applications monitoring the state of the BFD session.  A system MAY
/// > hold a session in Down state indefinitely (by simply refusing to
/// > advance the session state).  This may be done for operational or
/// > administrative reasons, among others.
///
pub struct Down {
    peer: IpAddr,
    log: Logger,
}

impl Down {
    pub(crate) fn new(peer: IpAddr, log: Logger) -> Self {
        Self { peer, log }
    }
}

impl State for Down {
    /// Run the send and receive functions for the BFD down state.
    fn run(
        &self,
        endpoint: BfdEndpoint,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
        kill_switch: Arc<AtomicBool>,
        db: rdb::Db,
    ) -> Result<(Box<dyn State>, BfdEndpoint)> {
        match self.peer {
            IpAddr::V4(addr) => db.disable_nexthop4(addr),
            IpAddr::V6(addr) => {
                warn!(
                    self.log,
                    "{addr} is down but active mode ipv6 not implemented yet"
                )
            }
        }
        loop {
            // Get an incoming message
            let (_addr, msg) =
                match self.recv(&endpoint, local, &remote, self.log.clone())? {
                    RecvResult::MessageFrom((addr, control)) => (addr, control),
                    RecvResult::TransitionTo(state) => {
                        return Ok((state, endpoint))
                    }
                };

            if kill_switch.load(Ordering::Relaxed) {
                return Err(anyhow!("killed"));
            }

            // Transition to the appropriate next state.
            use packet::State;
            match msg.state() {
                State::Peer(BfdPeerState::Down) => {
                    let next = Init::new(self.peer, self.log.clone());
                    return Ok((Box::new(next), endpoint));
                }
                State::Peer(BfdPeerState::Init) => {
                    let next = Up::new(self.peer, self.log.clone());
                    return Ok((Box::new(next), endpoint));
                }
                State::Peer(_) => {}
                State::Unknown(value) => {
                    wrn!(self; "unknown state: {} - ignoring", value);
                }
            }
        }
    }

    fn state(&self) -> BfdPeerState {
        BfdPeerState::Down
    }

    fn peer(&self) -> IpAddr {
        self.peer
    }
}

/// The BFD init state. The following is taken verbatim from the RFC.
///
/// > Init state means that the remote system is communicating, and the
/// > local system desires to bring the session up, but the remote system
/// > does not yet realize it.  A session will remain in Init state until
/// > either a BFD Control Packet is received that is signaling Init or Up
/// > state (in which case the session advances to Up state) or the
/// > Detection Time expires, meaning that communication with the remote
/// > system has been lost (in which case the session advances to Down
/// > state).
///
pub struct Init {
    peer: IpAddr,
    log: Logger,
}

impl Init {
    fn new(peer: IpAddr, log: Logger) -> Self {
        Self { peer, log }
    }
}

impl State for Init {
    /// Run the send and receive functions for the BFD init state.
    fn run(
        &self,
        endpoint: BfdEndpoint,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
        kill_switch: Arc<AtomicBool>,
        _db: rdb::Db,
    ) -> Result<(Box<dyn State>, BfdEndpoint)> {
        loop {
            // Get an incoming message
            let (_addr, msg) =
                match self.recv(&endpoint, local, &remote, self.log.clone())? {
                    RecvResult::MessageFrom((addr, control)) => (addr, control),
                    RecvResult::TransitionTo(state) => {
                        return Ok((state, endpoint))
                    }
                };

            if kill_switch.load(Ordering::Relaxed) {
                return Err(anyhow!("killed"));
            }

            // Transition to the appropriate next state.
            use packet::State;
            match msg.state() {
                State::Peer(BfdPeerState::AdminDown) => {
                    let next = Down::new(self.peer, self.log.clone());
                    return Ok((Box::new(next), endpoint));
                }
                State::Peer(BfdPeerState::Down) => {}
                State::Peer(_) => {
                    let next = Up::new(self.peer, self.log.clone());
                    return Ok((Box::new(next), endpoint));
                }
                State::Unknown(value) => {
                    wrn!(self; "unknown state: {} - ignoring", value);
                }
            }
        }
    }

    fn state(&self) -> BfdPeerState {
        BfdPeerState::Init
    }

    fn peer(&self) -> IpAddr {
        self.peer
    }
}

/// The BFD up state. The following is taken verbatim from the RFC.
///
/// > Up state means that the BFD session has successfully been
/// > established, and implies that connectivity between the systems is
/// > working.  The session will remain in the Up state until either
/// > connectivity fails or the session is taken down administratively.  If
/// > either the remote system signals Down state or the Detection Time
/// > expires, the session advances to Down state.
///
pub struct Up {
    peer: IpAddr,
    log: Logger,
}

impl Up {
    fn new(peer: IpAddr, log: Logger) -> Self {
        Self { peer, log }
    }
}

impl State for Up {
    /// Run the send and receive functions for the BFD up state.
    fn run(
        &self,
        endpoint: BfdEndpoint,
        local: PeerInfo,
        remote: Arc<Mutex<PeerInfo>>,
        kill_switch: Arc<AtomicBool>,
        db: rdb::Db,
    ) -> Result<(Box<dyn State>, BfdEndpoint)> {
        match self.peer {
            IpAddr::V4(addr) => db.enable_nexthop4(addr),
            IpAddr::V6(addr) => {
                warn!(
                    self.log,
                    "{addr} is up but active mode ipv6 not implemented yet"
                )
            }
        }
        loop {
            // Get an incoming message
            let (_addr, msg) =
                match self.recv(&endpoint, local, &remote, self.log.clone())? {
                    RecvResult::MessageFrom((addr, control)) => (addr, control),
                    RecvResult::TransitionTo(state) => {
                        return Ok((state, endpoint))
                    }
                };

            if kill_switch.load(Ordering::Relaxed) {
                return Err(anyhow!("killed"));
            }

            // Transition to the appropriate next state.
            use packet::State;
            match msg.state() {
                State::Peer(BfdPeerState::AdminDown)
                | State::Peer(BfdPeerState::Down) => {
                    let next = Down::new(self.peer, self.log.clone());
                    return Ok((Box::new(next), endpoint));
                }
                State::Peer(_) => {}
                State::Unknown(value) => {
                    wrn!(self; "unknown state: {} - ignoring", value);
                }
            }
        }
    }

    fn state(&self) -> BfdPeerState {
        BfdPeerState::Up
    }

    fn peer(&self) -> IpAddr {
        self.peer
    }
}
