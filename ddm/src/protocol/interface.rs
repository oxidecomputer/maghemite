// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The per-interface peering lifecycle, as a pure core.
//!
//! [`InterfaceSm::handle`] takes an [`Input`] and the current time and returns
//! the [`Action`]s to perform. It never reads a clock, opens a socket, or
//! touches the platform, so it compiles and is testable everywhere.
//!
//! The lifecycle is the same `Init -> Solicit -> Exchange` one the threaded
//! implementation runs, with the retry loops that used to live in a thread's
//! program counter -- waiting for an address object, binding the exchange
//! server, waiting for that server to answer, and the initial pull -- promoted
//! to explicit states with deadlines. [`InterfaceSm::next_deadline`] tells the
//! driver when to wake up and feed [`Input::Timer`].

use crate::discovery::Version;
use crate::protocol::rib::RibEvent;
use crate::sm::{AdminEvent, FsmState, PeerIdentity, PrefixSet};
use ddm_api_types::db::RouterKind;
use ddm_protocol_types::v3;
use std::collections::VecDeque;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Config {
    /// Address object to peer over. Must name an IPv6 link local address.
    pub aobj_name: String,

    /// This router's hostname, advertised to peers and pushed onto the path
    /// vector of originated prefixes.
    pub hostname: String,

    /// The kind of router this is, server or transit.
    pub kind: RouterKind,

    /// How long to wait between solicitations.
    pub solicit_interval: Duration,

    /// How long to go without hearing from a neighbor before expiring it.
    pub expire_threshold: Duration,

    /// How long to wait between attempts to resolve [`Config::aobj_name`].
    pub ip_addr_wait: Duration,

    /// How long to wait between attempts to bind the exchange server.
    pub exchange_bind_retry: Duration,

    /// How long to wait between probes of our own exchange server while
    /// waiting for it to start answering.
    pub exchange_ready_poll: Duration,
}

/// The addressing [`Config::aobj_name`] resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub ifname: String,
    pub index: u32,
    pub addr: Ipv6Addr,
}

/// A decoded discovery packet.
#[derive(Clone, Debug)]
pub enum Discovery {
    Solicit,
    Advertise {
        hostname: String,
        kind: RouterKind,
        version: u8,
    },
}

#[derive(Debug)]
pub enum Input {
    /// Result of an [`Action::ResolveAddr`]. `None` if the address object does
    /// not exist yet or is not IPv6.
    Addr(Option<IfAddr>),

    /// A discovery packet arrived from `from`.
    Discovery {
        from: Ipv6Addr,
        packet: Discovery,
    },

    /// A solicitation could not be sent. The link is presumed gone.
    SolicitFailed,

    /// Our peer pushed an update to us over the exchange server.
    PeerPush(Box<v3::Update>),

    /// The hub asks us to pass an update on to our peer.
    Redistribute(Box<v3::Update>),

    Admin(AdminEvent),

    /// Result of a previously emitted action.
    Outcome(Outcome),

    /// A deadline from [`InterfaceSm::next_deadline`] elapsed.
    Timer,
}

#[derive(Debug)]
pub enum Outcome {
    ExchangeServerStarted(bool),
    SelfPull(bool),
    /// `None` on failure, otherwise the peer's table as an announcement.
    PeerPull(Option<Box<v3::Update>>),
    UpdateSent(bool),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Look up [`Config::aobj_name`] and report back with [`Input::Addr`].
    ResolveAddr,

    /// Bring up the discovery sockets on the given address.
    OpenSockets(IfAddr),
    CloseSockets,

    /// Bind the exchange server to our own address.
    StartExchangeServer,
    StopExchangeServer,

    /// Pull from our own exchange server to find out whether it is answering.
    SelfPull,

    PeerPull {
        peer: Ipv6Addr,
        version: Version,
    },

    /// Multicast a solicitation.
    Solicit,

    /// Unicast an advertisement to `to`.
    Advertise {
        to: Ipv6Addr,
    },

    SendUpdate {
        peer: Ipv6Addr,
        version: Version,
        update: Box<v3::Update>,
    },

    Rib(RibEvent),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub solicitations_sent: u64,
    pub solicitations_received: u64,
    pub advertisements_sent: u64,
    pub advertisements_received: u64,
    pub peer_expirations: u64,
    pub peer_address_changes: u64,
    pub peer_established: u64,
    pub updates_sent: u64,
    pub updates_received: u64,
    pub update_send_fail: u64,
}

/// What the admin API and oximeter see. Published by the driver over a watch
/// channel.
#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub state: FsmState,
    pub since: Instant,
    pub if_index: u32,
    pub if_name: String,
    pub peer: Option<PeerIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Startup {
    /// Retrying the exchange server bind.
    Bind,
    /// Bound; polling ourselves until the server answers.
    SelfPull,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    WaitAddr,
    Solicit,
    /// Peered, but the exchange server is not serving yet. Reported as
    /// [`FsmState::Exchange`], matching the threaded implementation, which
    /// transitioned before entering its bind retry loop.
    Starting(Startup),
    Exchange,
}

/// The single outstanding exchange operation, if any. Exchange operations are
/// serialized because ddm is a delta protocol: a peer that sees an announce and
/// a withdraw out of order ends up with the wrong table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    ServerStart,
    SelfPull,
    Pull { initial: bool },
    Send,
}

struct Neighbor {
    identity: PeerIdentity,
    version: Version,
    last_seen: Instant,
}

pub struct InterfaceSm {
    config: Config,
    state: State,
    since: Instant,
    addr: Option<IfAddr>,
    neighbor: Option<Neighbor>,

    /// An [`Action::ResolveAddr`] is outstanding.
    resolving: bool,
    resolve_at: Instant,
    solicit_at: Instant,

    /// When the current state's retry may next fire. Meaning depends on the
    /// state: the bind retry, the self-pull poll, or the initial pull retry.
    retry_at: Option<Instant>,

    outbound: VecDeque<Box<v3::Update>>,
    pending: Option<Pending>,
    initial_pull_done: bool,
    sync_requested: bool,

    counters: Counters,
}

impl InterfaceSm {
    pub fn new(config: Config, now: Instant) -> Self {
        Self {
            config,
            state: State::WaitAddr,
            since: now,
            addr: None,
            neighbor: None,
            resolving: false,
            resolve_at: now,
            solicit_at: now,
            retry_at: None,
            outbound: VecDeque::new(),
            pending: None,
            initial_pull_done: false,
            sync_requested: false,
            counters: Counters::default(),
        }
    }

    pub fn handle(&mut self, input: Input, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();
        match input {
            Input::Addr(addr) => self.on_addr(addr, now, &mut out),
            Input::Discovery { from, packet } => {
                self.on_discovery(from, packet, now, &mut out);
            }
            Input::SolicitFailed => self.enter_wait_addr(now, &mut out),
            Input::PeerPush(update) => self.on_peer_push(update, &mut out),
            Input::Redistribute(update) => self.on_redistribute(*update),
            Input::Admin(event) => self.on_admin(event, now, &mut out),
            Input::Outcome(outcome) => self.on_outcome(outcome, now, &mut out),
            Input::Timer => {}
        }
        self.tick(now, &mut out);
        out
    }

    /// When the driver should next feed [`Input::Timer`].
    pub fn next_deadline(&self) -> Option<Instant> {
        let mut deadlines = Vec::new();
        if self.state == State::WaitAddr {
            if !self.resolving {
                deadlines.push(self.resolve_at);
            }
        } else {
            deadlines.push(self.solicit_at);
            if let Some(n) = &self.neighbor {
                deadlines.push(n.last_seen + self.config.expire_threshold);
            }
            if self.pending.is_none()
                && let Some(t) = self.retry_at
            {
                deadlines.push(t);
            }
        }
        deadlines.into_iter().min()
    }

    pub fn status(&self) -> Status {
        Status {
            state: self.fsm_state(),
            since: self.since,
            if_index: self.addr.as_ref().map_or(0, |a| a.index),
            if_name: self
                .addr
                .as_ref()
                .map_or_else(String::new, |a| a.ifname.clone()),
            peer: self.neighbor.as_ref().map(|n| n.identity.clone()),
        }
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    fn fsm_state(&self) -> FsmState {
        match self.state {
            State::WaitAddr => FsmState::Init,
            State::Solicit => FsmState::Solicit,
            State::Starting(_) | State::Exchange => FsmState::Exchange,
        }
    }

    /// `since` tracks the externally visible [`FsmState`], so the internal
    /// `Starting -> Exchange` step does not restart the clock.
    fn set_state(&mut self, state: State, now: Instant) {
        let before = self.fsm_state();
        self.state = state;
        if self.fsm_state() != before {
            self.since = now;
        }
    }

    fn peer(&self) -> Option<(Ipv6Addr, Version)> {
        self.neighbor.as_ref().map(|n| (n.identity.addr, n.version))
    }

    fn on_addr(
        &mut self,
        addr: Option<IfAddr>,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if self.state != State::WaitAddr {
            return;
        }
        self.resolving = false;
        match addr {
            Some(addr) => {
                out.push(Action::OpenSockets(addr.clone()));
                self.addr = Some(addr);
                self.solicit_at = now;
                self.set_state(State::Solicit, now);
            }
            None => self.resolve_at = now + self.config.ip_addr_wait,
        }
    }

    fn on_discovery(
        &mut self,
        from: Ipv6Addr,
        packet: Discovery,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if self.state == State::WaitAddr {
            return;
        }
        match packet {
            Discovery::Solicit => {
                self.counters.solicitations_received += 1;
                self.counters.advertisements_sent += 1;
                out.push(Action::Advertise { to: from });
            }
            Discovery::Advertise {
                hostname,
                kind,
                version,
            } => {
                self.counters.advertisements_received += 1;
                // TODO: version negotiation. Unknown versions are dropped
                // rather than negotiated down.
                let version = match version {
                    2 => Version::V2,
                    3 => Version::V3,
                    _ => return,
                };
                self.on_advertisement(
                    PeerIdentity {
                        addr: from,
                        hostname,
                        kind,
                    },
                    version,
                    now,
                );
            }
        }
    }

    fn on_advertisement(
        &mut self,
        identity: PeerIdentity,
        version: Version,
        now: Instant,
    ) {
        let changed = match &self.neighbor {
            None => {
                self.counters.peer_established += 1;
                true
            }
            Some(n) => {
                if n.identity.addr != identity.addr {
                    self.counters.peer_address_changes += 1;
                }
                n.identity != identity
            }
        };

        self.neighbor = Some(Neighbor {
            identity,
            version,
            last_seen: now,
        });

        // A peer that renumbers or renames mid-exchange is picked up in place:
        // the exchange server is bound to *our* address, so only the
        // destination of subsequent sends changes, and that is read back out of
        // the neighbor.
        if changed && self.state == State::Solicit {
            self.set_state(State::Starting(Startup::Bind), now);
            self.retry_at = Some(now);
        }
    }

    fn on_peer_push(&mut self, update: Box<v3::Update>, out: &mut Vec<Action>) {
        if !matches!(self.state, State::Starting(_) | State::Exchange) {
            return;
        }
        self.counters.updates_received += 1;
        let (Some(addr), Some((peer, _))) = (&self.addr, self.peer()) else {
            return;
        };
        out.push(Action::Rib(RibEvent::Update {
            peer,
            ifname: addr.ifname.clone(),
            update,
        }));
    }

    fn on_redistribute(&mut self, update: v3::Update) {
        if self.state != State::Exchange {
            return;
        }
        // Only the underlay half is forwarded. Tunnel endpoints reach their
        // peers through the originator's own exchange, never through a
        // redistributing router.
        let Some(underlay) = update.underlay else {
            return;
        };
        if !underlay.announce.is_empty() {
            self.enqueue(v3::UnderlayUpdate::announce(underlay.announce));
        }
        if !underlay.withdraw.is_empty() {
            self.enqueue(v3::UnderlayUpdate::withdraw(underlay.withdraw));
        }
    }

    fn on_admin(
        &mut self,
        event: AdminEvent,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        if self.state != State::Exchange {
            return;
        }
        match event {
            AdminEvent::Announce(PrefixSet::Underlay(prefixes)) => {
                self.enqueue(v3::UnderlayUpdate::announce(
                    self.originate(&prefixes),
                ));
            }
            AdminEvent::Withdraw(PrefixSet::Underlay(prefixes)) => {
                self.enqueue(v3::UnderlayUpdate::withdraw(
                    self.originate(&prefixes),
                ));
            }
            AdminEvent::Announce(PrefixSet::Tunnel(endpoints)) => {
                self.enqueue(v3::TunnelUpdate::announce(endpoints));
            }
            AdminEvent::Withdraw(PrefixSet::Tunnel(endpoints)) => {
                self.enqueue(v3::TunnelUpdate::withdraw(endpoints));
            }
            AdminEvent::Expire(peer) => {
                if self.peer().is_some_and(|(a, _)| a == peer) {
                    self.expire_peer(out);
                    self.set_state(State::Solicit, now);
                }
            }
            AdminEvent::Sync => self.sync_requested = true,
        }
    }

    fn originate(
        &self,
        prefixes: &std::collections::HashSet<oxnet::Ipv6Net>,
    ) -> std::collections::HashSet<v3::PathVector> {
        prefixes
            .iter()
            .map(|destination| v3::PathVector {
                destination: *destination,
                path: vec![self.config.hostname.clone()],
            })
            .collect()
    }

    fn enqueue(&mut self, update: impl Into<v3::Update>) {
        self.outbound.push_back(Box::new(update.into()));
    }

    fn on_outcome(
        &mut self,
        outcome: Outcome,
        now: Instant,
        out: &mut Vec<Action>,
    ) {
        match (self.pending, outcome) {
            (
                Some(Pending::ServerStart),
                Outcome::ExchangeServerStarted(ok),
            ) => {
                self.pending = None;
                if ok {
                    self.set_state(State::Starting(Startup::SelfPull), now);
                    self.retry_at = Some(now);
                } else {
                    self.retry_at = Some(now + self.config.exchange_bind_retry);
                }
            }
            (Some(Pending::SelfPull), Outcome::SelfPull(ok)) => {
                self.pending = None;
                if ok {
                    self.initial_pull_done = false;
                    self.set_state(State::Exchange, now);
                    self.retry_at = Some(now);
                } else {
                    self.retry_at = Some(now + self.config.exchange_ready_poll);
                }
            }
            (Some(Pending::Pull { initial }), Outcome::PeerPull(result)) => {
                self.pending = None;
                match result {
                    Some(update) => {
                        if initial {
                            self.initial_pull_done = true;
                            self.retry_at = None;
                        }
                        self.on_peer_push(update, out);
                    }
                    None if initial => {
                        self.retry_at =
                            Some(now + self.config.solicit_interval);
                    }
                    None => {}
                }
            }
            (Some(Pending::Send), Outcome::UpdateSent(ok)) => {
                self.pending = None;
                if !ok {
                    self.counters.update_send_fail += 1;
                    self.expire_peer(out);
                    self.set_state(State::Solicit, now);
                }
            }
            // An outcome for work this state machine no longer cares about,
            // e.g. a send that completed after the peer was expired.
            _ => {}
        }
    }

    fn tick(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.state == State::WaitAddr {
            if !self.resolving && now >= self.resolve_at {
                self.resolving = true;
                out.push(Action::ResolveAddr);
            }
            return;
        }

        // Inclusive, because `next_deadline` publishes exactly this instant. A
        // strict comparison leaves a deadline in the past that nothing can
        // clear, and the driver spins on it.
        if self.neighbor.as_ref().is_some_and(|n| {
            now.duration_since(n.last_seen) >= self.config.expire_threshold
        }) {
            self.counters.peer_expirations += 1;
            self.expire_peer(out);
            self.set_state(State::Solicit, now);
        }

        if now >= self.solicit_at {
            self.solicit_at = now + self.config.solicit_interval;
            self.counters.solicitations_sent += 1;
            out.push(Action::Solicit);
        }

        self.pump(now, out);
    }

    fn pump(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.pending.is_some() {
            return;
        }
        let Some((peer, version)) = self.peer() else {
            return;
        };
        let due = |at: Option<Instant>| at.is_some_and(|t| now >= t);

        match self.state {
            State::Starting(Startup::Bind) if due(self.retry_at) => {
                self.retry_at = None;
                self.pending = Some(Pending::ServerStart);
                out.push(Action::StartExchangeServer);
            }
            State::Starting(Startup::SelfPull) if due(self.retry_at) => {
                self.retry_at = None;
                self.pending = Some(Pending::SelfPull);
                out.push(Action::SelfPull);
            }
            State::Exchange => {
                if let Some(update) = self.outbound.pop_front() {
                    self.counters.updates_sent += 1;
                    self.pending = Some(Pending::Send);
                    out.push(Action::SendUpdate {
                        peer,
                        version,
                        update,
                    });
                } else if !self.initial_pull_done && due(self.retry_at) {
                    self.retry_at = None;
                    self.pending = Some(Pending::Pull { initial: true });
                    out.push(Action::PeerPull { peer, version });
                } else if self.sync_requested {
                    self.sync_requested = false;
                    self.pending = Some(Pending::Pull { initial: false });
                    out.push(Action::PeerPull { peer, version });
                }
            }
            _ => {}
        }
    }

    /// Drop the peer and everything learned through it. The caller decides
    /// which state to land in.
    fn expire_peer(&mut self, out: &mut Vec<Action>) {
        let Some(neighbor) = self.neighbor.take() else {
            return;
        };
        if matches!(self.state, State::Starting(_) | State::Exchange) {
            out.push(Action::StopExchangeServer);
        }
        out.push(Action::Rib(RibEvent::PeerExpired {
            nexthop: neighbor.identity.addr,
        }));
        self.outbound.clear();
        self.pending = None;
        self.sync_requested = false;
        self.initial_pull_done = false;
        self.retry_at = None;
    }

    fn enter_wait_addr(&mut self, now: Instant, out: &mut Vec<Action>) {
        if self.state == State::WaitAddr {
            return;
        }
        self.expire_peer(out);
        out.push(Action::CloseSockets);
        self.addr = None;
        self.resolving = false;
        self.resolve_at = now;
        self.set_state(State::WaitAddr, now);
    }
}

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
