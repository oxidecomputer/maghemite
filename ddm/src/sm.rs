// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::db::{Db, RouterKind};
use crate::discovery::Version;
use crate::exchange::{PathVector, TunnelUpdate, UnderlayUpdate, Update};
use crate::{dbg, discovery, err, exchange, inf, wrn};
use libnet::get_ipaddr_info;
use libnet::Ipv6Net;
use mg_common::net::TunnelOrigin;
use slog::Logger;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug)]
pub enum AdminEvent {
    /// Announce a set of IPv6 prefixes
    Announce(PrefixSet),

    /// Withdraw a set of IPv6 prefixes
    Withdraw(PrefixSet),

    /// Expire the peer at the specified address
    Expire(Ipv6Addr),

    /// Synchronize with active peers by pulling their prefixes.
    Sync,
}

#[derive(Debug)]
pub enum PrefixSet {
    Underlay(HashSet<Ipv6Net>),
    Tunnel(HashSet<TunnelOrigin>),
}

#[derive(Debug)]
pub enum PeerEvent {
    Push(Update),
}

#[derive(Debug)]
pub enum NeighborEvent {
    Advertise((Ipv6Addr, Version)),
    SolicitFail,
    Expire,
}

#[derive(Debug)]
pub enum Event {
    Neighbor(NeighborEvent),
    Peer(PeerEvent),
    Admin(AdminEvent),
}

impl From<NeighborEvent> for Event {
    fn from(e: NeighborEvent) -> Self {
        Self::Neighbor(e)
    }
}

impl From<PeerEvent> for Event {
    fn from(e: PeerEvent) -> Self {
        Self::Peer(e)
    }
}

impl From<AdminEvent> for Event {
    fn from(e: AdminEvent) -> Self {
        Self::Admin(e)
    }
}

#[derive(Debug)]
pub enum StateType {
    Solicit,
    Exchange,
}

#[derive(Debug)]
pub enum EventError {
    InvalidEvent(StateType),
}

#[derive(Debug)]
pub enum EventResponse {
    Success,
    Prefixes(Vec<Ipv6Net>),
}

#[derive(Error, Debug)]
pub enum SmError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("discovery error: {0}")]
    Discovery(#[from] discovery::DiscoveryError),
}

#[derive(Clone)]
pub struct Config {
    /// Interface this state machine is associated with.
    pub if_index: u32,

    /// Interface name this state machine is associated with.
    pub if_name: String,

    /// Address object name the state machine uses for peering. Must correspond
    /// to IPv6 link local address.
    pub aobj_name: String,

    /// Link local Ipv6 address this state machine is associated with
    pub addr: Ipv6Addr,

    /// How long to wait between solicitations (milliseconds).
    pub solicit_interval: u64,

    /// How often to check for link failure while waiting for discovery messges.
    pub discovery_read_timeout: u64,

    /// How long to wait between attempts to get an IP address for a specified
    /// address object.
    pub ip_addr_wait: u64,

    /// How long to wait without a solicitation response before expiring a peer
    /// (milliseconds).
    pub expire_threshold: u64,

    /// How long to wait for a response to exchange messages.
    pub exchange_timeout: u64,

    /// The kind of router this is, server or transit.
    pub kind: RouterKind,

    /// TCP port to use for prefix exchange.
    pub exchange_port: u16,

    /// Dendrite dpd config
    pub dpd: Option<DpdConfig>,
}

#[derive(Clone)]
pub struct DpdConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Default)]
pub struct SessionStats {
    // Discovery
    pub solicitations_sent: AtomicU64,
    pub solicitations_received: AtomicU64,
    pub advertisements_sent: AtomicU64,
    pub advertisements_received: AtomicU64,
    pub peer_expirations: AtomicU64,
    pub peer_address_changes: AtomicU64,
    pub peer_established: AtomicU64,
    pub peer_address: Mutex<Option<Ipv6Addr>>,

    // Exchange
    pub updates_sent: AtomicU64,
    pub updates_received: AtomicU64,
    pub imported_underlay_prefixes: AtomicU64,
    pub imported_tunnel_endpoints: AtomicU64,
    pub update_send_fail: AtomicU64,
}

#[derive(Clone)]
pub struct SmContext {
    pub config: Config,
    pub db: Db,
    pub tx: Sender<Event>,
    pub event_channels: Vec<Sender<Event>>,
    pub rt: Arc<tokio::runtime::Handle>,
    pub hostname: String,
    pub stats: Arc<SessionStats>,
    pub log: Logger,
}

pub struct StateMachine {
    pub ctx: SmContext,
    pub rx: Option<Receiver<Event>>,
}

impl StateMachine {
    pub fn run(&mut self) -> Result<(), SmError> {
        let ctx = self.ctx.clone();
        let mut rx = self.rx.take().unwrap();
        let log = self.ctx.log.clone();
        spawn(move || {
            let mut state: Box<dyn State> =
                Box::new(Init::new(ctx.clone(), log.clone()));
            loop {
                (state, rx) = state.run(rx);
            }
        });

        Ok(())
    }
}

trait State {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Box<dyn State>, Receiver<Event>);
}

struct Init {
    ctx: SmContext,
    log: Logger,
}

impl Init {
    fn new(ctx: SmContext, log: Logger) -> Self {
        Self { ctx, log }
    }
}

impl State for Init {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Box<dyn State>, Receiver<Event>) {
        loop {
            let info = match get_ipaddr_info(&self.ctx.config.aobj_name) {
                Ok(info) => info,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "failed to get IPv6 address for interface {}: {}",
                        &self.ctx.config.aobj_name,
                        e
                    );
                    sleep(Duration::from_millis(self.ctx.config.ip_addr_wait));
                    continue;
                }
            };
            let addr = match info.addr {
                IpAddr::V6(a) => a,
                IpAddr::V4(_) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "specified address {} is not IPv6",
                        &self.ctx.config.aobj_name
                    );
                    sleep(Duration::from_millis(self.ctx.config.ip_addr_wait));
                    continue;
                }
            };
            self.ctx.config.if_name.clone_from(&info.ifname);
            self.ctx.config.if_index = info.index as u32;
            self.ctx.config.addr = addr;
            inf!(
                self.log,
                self.ctx.config.if_name,
                "sm initialized with addr {} on if {} index {}",
                &addr,
                &info.ifname,
                info.index,
            );

            // Now that we have an ip address to run discovery on, start the
            // discovery handler and jump into the solicit state.
            discovery::handler(
                self.ctx.hostname.clone(),
                self.ctx.config.clone(),
                self.ctx.tx.clone(),
                self.ctx.db.clone(),
                self.ctx.stats.clone(),
                self.ctx.log.clone(),
            )
            .unwrap(); // TODO unwrap
            return (
                Box::new(Solicit::new(self.ctx.clone(), self.log.clone())),
                event,
            );
        }
    }
}

struct Solicit {
    ctx: SmContext,
    log: Logger,
}

impl Solicit {
    fn new(ctx: SmContext, log: Logger) -> Self {
        Self { ctx, log }
    }
}

impl State for Solicit {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Box<dyn State>, Receiver<Event>) {
        loop {
            let e = match event.recv() {
                Ok(e) => e,
                Err(e) => {
                    err!(
                        self.log,
                        self.ctx.config.if_name,
                        "solicit event recv: {}",
                        e
                    );
                    continue;
                }
            };
            match e {
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    dbg!(
                        self.log,
                        self.ctx.config.if_name,
                        "transition solicit -> exchange"
                    );
                    return (
                        Box::new(Exchange::new(
                            self.ctx.clone(),
                            addr,
                            version,
                            self.log.clone(),
                        )),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Expire) => {}
                Event::Neighbor(NeighborEvent::SolicitFail) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "exiting solicit state due to failed solicit",
                    );
                    return (
                        Box::new(Init::new(self.ctx.clone(), self.log.clone())),
                        event,
                    );
                }
                Event::Peer(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "peer event in solicit state: {:?}",
                        e
                    );
                }
                Event::Admin(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "admin event in solicit state: {:?}",
                        e
                    );
                }
            }
        }
    }
}

pub struct Exchange {
    pub peer: Ipv6Addr,
    version: Version,
    ctx: SmContext,
    log: Logger,
}

impl Exchange {
    fn new(
        ctx: SmContext,
        peer: Ipv6Addr,
        version: Version,
        log: Logger,
    ) -> Self {
        Self {
            ctx,
            peer,
            version,
            log,
        }
    }

    fn initial_pull(&self, stop: Arc<AtomicBool>) {
        let ctx = self.ctx.clone();
        let peer = self.peer;
        let version = self.version;
        let rt = self.ctx.rt.clone();
        let log = self.log.clone();
        let interval = self.ctx.config.solicit_interval;
        let if_name = self.ctx.config.if_name.clone();

        spawn(move || {
            while let Err(e) = crate::exchange::pull(
                ctx.clone(),
                peer,
                version,
                rt.clone(),
                log.clone(),
            ) {
                sleep(Duration::from_millis(interval));
                wrn!(log, if_name, "exchange pull: {}", e);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        });
    }

    fn wait_for_exchange_server_to_start(&self) {
        inf!(
            self.log,
            self.ctx.config.if_name,
            "waiting for exchange server to start"
        );
        let interval = 250; // TODO as parameter
        loop {
            match exchange::do_pull(
                &self.ctx,
                &self.ctx.config.addr,
                &self.ctx.rt,
            ) {
                Ok(_) => break,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "exchange server not started: {e}",
                    );
                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "retrying in {interval} ms",
                    );
                    sleep(Duration::from_millis(interval))
                }
            }
        }
    }

    fn expire_peer(
        &mut self,
        exchange_thread: &tokio::task::JoinHandle<()>,
        pull_stop: &AtomicBool,
    ) {
        exchange_thread.abort();
        self.ctx.db.remove_peer(self.ctx.config.if_index);
        let (to_remove, to_remove_tnl) =
            self.ctx.db.remove_nexthop_routes(self.peer);
        let mut routes: Vec<crate::sys::Route> = Vec::new();
        for x in &to_remove {
            let mut r: crate::sys::Route = x.clone().into();
            r.ifname.clone_from(&self.ctx.config.if_name);
            routes.push(r);
        }
        crate::sys::remove_underlay_routes(
            &self.log,
            &self.ctx.config.if_name,
            &self.ctx.config.dpd,
            routes,
            &self.ctx.rt,
        );
        if let Err(e) = crate::sys::remove_tunnel_routes(
            &self.log,
            &self.ctx.config.if_name,
            &to_remove_tnl,
        ) {
            err!(
                self.log,
                self.ctx.config.if_name,
                "failed to remove tunnel routes: {:#?} {e}",
                to_remove_tnl
            );
        }
        // if we're a transit router propagate withdraws for the
        // expired peer.
        if self.ctx.config.kind == RouterKind::Transit {
            dbg!(
                self.log,
                self.ctx.config.if_name,
                "redistributing expire to {} peers",
                self.ctx.event_channels.len()
            );

            let underlay = if to_remove.is_empty() {
                None
            } else {
                Some(UnderlayUpdate::withdraw(
                    to_remove
                        .iter()
                        .map(|x| PathVector {
                            destination: x.destination,
                            path: {
                                let mut ps = x.path.clone();
                                ps.push(self.ctx.hostname.clone());
                                ps
                            },
                        })
                        .collect(),
                ))
            };

            let tunnel = if to_remove_tnl.is_empty() {
                None
            } else {
                Some(TunnelUpdate::withdraw(
                    to_remove_tnl.iter().cloned().map(Into::into).collect(),
                ))
            };

            let push = Update { underlay, tunnel };
            for ec in &self.ctx.event_channels {
                ec.send(Event::Peer(PeerEvent::Push(push.clone()))).unwrap();
            }
        }
        pull_stop.store(true, Ordering::Relaxed);
    }
}

impl State for Exchange {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Box<dyn State>, Receiver<Event>) {
        let exchange_thread = loop {
            match exchange::handler(
                self.ctx.clone(),
                self.ctx.config.addr,
                self.peer,
                self.log.clone(),
            ) {
                Ok(handle) => break handle,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "exchange handler start: {e}",
                    );
                    inf!(self.log, self.ctx.config.if_name, "retrying in 1 s",);
                    sleep(Duration::from_secs(1));
                    continue;
                }
            }
        };

        self.wait_for_exchange_server_to_start();

        let pull_stop = Arc::new(AtomicBool::new(false));

        // Do an initial pull, in the event that exchange events are fired while
        // this pull is taking place, they will be queued and handled in the
        // loop below.
        self.initial_pull(pull_stop.clone());

        loop {
            let e = match event.recv() {
                Ok(e) => e,
                Err(e) => {
                    err!(
                        self.log,
                        self.ctx.config.if_name,
                        "exchange event recv: {}",
                        e
                    );
                    continue;
                }
            };
            match e {
                Event::Admin(AdminEvent::Announce(PrefixSet::Underlay(
                    prefixes,
                ))) => {
                    let pv: HashSet<PathVector> = prefixes
                        .iter()
                        .map(|x| PathVector {
                            destination: *x,
                            path: vec![self.ctx.hostname.clone()],
                        })
                        .collect();
                    if let Err(e) = crate::exchange::announce_underlay(
                        &self.ctx,
                        self.ctx.config.clone(),
                        pv,
                        self.peer,
                        self.version,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "announce: {}",
                            e,
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed announce",
                            self.peer,
                        );
                        self.expire_peer(&exchange_thread, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::Announce(PrefixSet::Tunnel(
                    endpoints,
                ))) => {
                    let tv: HashSet<TunnelOrigin> = endpoints.clone();
                    if let Err(e) = crate::exchange::announce_tunnel(
                        &self.ctx,
                        self.ctx.config.clone(),
                        tv,
                        self.peer,
                        self.version,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "announce tunnel: {}",
                            e,
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed tunnel announce",
                            self.peer,
                        );
                        self.expire_peer(&exchange_thread, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::Withdraw(PrefixSet::Underlay(
                    prefixes,
                ))) => {
                    let pv: HashSet<PathVector> = prefixes
                        .iter()
                        .map(|x| PathVector {
                            destination: *x,
                            path: vec![self.ctx.hostname.clone()],
                        })
                        .collect();
                    if let Err(e) = crate::exchange::withdraw_underlay(
                        &self.ctx,
                        self.ctx.config.clone(),
                        pv,
                        self.peer,
                        self.version,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "withdraw: {}",
                            e,
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed withdraw",
                            self.peer,
                        );
                        self.expire_peer(&exchange_thread, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::Withdraw(PrefixSet::Tunnel(
                    endpoints,
                ))) => {
                    let tv: HashSet<TunnelOrigin> = endpoints.clone();
                    if let Err(e) = crate::exchange::withdraw_tunnel(
                        &self.ctx,
                        self.ctx.config.clone(),
                        tv,
                        self.peer,
                        self.version,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "withdraw tunnel: {}",
                            e,
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed tunnel withdraw",
                            self.peer,
                        );
                        self.expire_peer(&exchange_thread, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::Expire(peer)) => {
                    if self.peer == peer {
                        inf!(
                            self.log,
                            self.ctx.config.if_name,
                            "administratively expiring peer {}",
                            peer,
                        );
                        self.expire_peer(&exchange_thread, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::Sync) => {
                    if let Err(e) = crate::exchange::pull(
                        self.ctx.clone(),
                        self.peer,
                        self.version,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "exchange pull: {}",
                            e
                        );
                    }
                }
                // TODO tunnel
                Event::Peer(PeerEvent::Push(update)) => {
                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "push from {}: {:#?}",
                        self.peer,
                        update,
                    );
                    if let Some(push) = update.underlay {
                        if !push.announce.is_empty() {
                            if let Err(e) = crate::exchange::announce_underlay(
                                &self.ctx,
                                self.ctx.config.clone(),
                                push.announce,
                                self.peer,
                                self.version,
                                self.ctx.rt.clone(),
                                self.log.clone(),
                            ) {
                                err!(
                                    self.log,
                                    self.ctx.config.if_name,
                                    "announce: {}",
                                    e,
                                );
                                wrn!(
                                    self.log,
                                    self.ctx.config.if_name,
                                    "expiring peer {} due to failed announce",
                                    self.peer,
                                );
                                self.expire_peer(&exchange_thread, &pull_stop);
                                return (
                                    Box::new(Solicit::new(
                                        self.ctx.clone(),
                                        self.log.clone(),
                                    )),
                                    event,
                                );
                            }
                        }
                        if !push.withdraw.is_empty() {
                            if let Err(e) = crate::exchange::withdraw_underlay(
                                &self.ctx,
                                self.ctx.config.clone(),
                                push.withdraw,
                                self.peer,
                                self.version,
                                self.ctx.rt.clone(),
                                self.log.clone(),
                            ) {
                                err!(
                                    self.log,
                                    self.ctx.config.if_name,
                                    "withdraw: {}",
                                    e,
                                );
                                wrn!(
                                    self.log,
                                    self.ctx.config.if_name,
                                    "expiring peer {} due to failed withdraw",
                                    self.peer,
                                );
                                self.expire_peer(&exchange_thread, &pull_stop);
                                return (
                                    Box::new(Solicit::new(
                                        self.ctx.clone(),
                                        self.log.clone(),
                                    )),
                                    event,
                                );
                            }
                        }
                    }
                }
                Event::Neighbor(NeighborEvent::Expire) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to discovery event",
                        self.peer,
                    );
                    self.expire_peer(&exchange_thread, &pull_stop);
                    return (
                        Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        )),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::SolicitFail) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed solicit",
                        self.peer,
                    );
                    self.expire_peer(&exchange_thread, &pull_stop);
                    return (
                        Box::new(Init::new(self.ctx.clone(), self.log.clone())),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    self.peer = addr;
                    self.version = version;
                }
            }
        }
    }
}
