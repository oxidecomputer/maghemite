// Copyright 2022 Oxide Computer Company

use crate::db::{Db, Ipv6Prefix, RouterKind};
use crate::{dbg, discovery, err, exchange, wrn};
use slog::{error, Logger};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::sleep;
use std::thread::spawn;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug)]
pub enum AdminEvent {
    Announce(HashSet<Ipv6Prefix>),
    Withdraw(HashSet<Ipv6Prefix>),
    Sync,
}

#[derive(Debug)]
pub struct Push {
    pub announce: HashSet<Ipv6Prefix>,
    pub withdraw: HashSet<Ipv6Prefix>,
}

#[derive(Debug)]
pub enum PeerEvent {
    Push(Push),
}

#[derive(Debug)]
pub enum NeighborEvent {
    Advertise(Ipv6Addr),
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
    Prefixes(Vec<Ipv6Prefix>),
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

    /// Link local Ipv6 address this state machine is associated with
    pub addr: Ipv6Addr,

    /// How long to wait between solicitations (milliseconds).
    pub solicit_interval: u64,

    /// How long to wait without a solicitation response before expiring a peer
    /// (milliseconds).
    pub expire_threshold: u64,

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

#[derive(Clone)]
pub struct SmContext {
    pub config: Config,
    pub db: Db,
    pub tx: Sender<Event>,
    pub event_channels: Vec<Sender<Event>>,
    pub rt: Arc<tokio::runtime::Handle>,
    pub log: Logger,
}

pub struct StateMachine {
    pub ctx: SmContext,
    pub rx: Option<Receiver<Event>>,
}

impl StateMachine {
    pub fn run(&mut self) -> Result<(), SmError> {
        discovery::handler(
            self.ctx.config.clone(),
            self.ctx.tx.clone(),
            self.ctx.db.clone(),
            self.ctx.log.clone(),
        )?;

        let ctx = self.ctx.clone();
        let mut rx = self.rx.take().unwrap();
        let log = self.ctx.log.clone();
        spawn(move || {
            let mut state: Box<dyn State> =
                Box::new(Solicit::new(ctx.clone(), log.clone()));
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
                        self.ctx.config.if_index,
                        "solicit event recv: {}",
                        e
                    );
                    continue;
                }
            };
            match e {
                Event::Neighbor(NeighborEvent::Advertise(addr)) => {
                    dbg!(
                        self.log,
                        self.ctx.config.if_index,
                        "transition solicit -> exchange"
                    );
                    return (
                        Box::new(Exchange::new(
                            self.ctx.clone(),
                            addr,
                            self.log.clone(),
                        )),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Expire) => {}
                Event::Peer(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_index,
                        "peer event in solicit state: {:?}",
                        e
                    );
                }
                Event::Admin(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_index,
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
    ctx: SmContext,
    log: Logger,
}

impl Exchange {
    fn new(ctx: SmContext, peer: Ipv6Addr, log: Logger) -> Self {
        Self { ctx, peer, log }
    }

    fn initial_pull(&self, stop: Arc<AtomicBool>) {
        let ctx = self.ctx.clone();
        let peer = self.peer;
        let rt = self.ctx.rt.clone();
        let log = self.log.clone();
        let interval = self.ctx.config.solicit_interval;
        let if_index = self.ctx.config.if_index;

        spawn(move || {
            while let Err(e) = crate::exchange::pull(
                ctx.clone(),
                peer,
                rt.clone(),
                log.clone(),
            ) {
                sleep(Duration::from_millis(interval));
                wrn!(log, if_index, "exchange pull: {}", e);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        });
    }
}

impl State for Exchange {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Box<dyn State>, Receiver<Event>) {
        let exchange_thread = exchange::handler(
            self.ctx.clone(),
            self.ctx.config.addr,
            self.peer,
            self.log.clone(),
        )
        .unwrap(); //TODO unwrap

        let pull_stop = Arc::new(AtomicBool::new(false));

        // Do an initial pull, in the event that exchange events are fired while
        // this pull is taking place, they will be queued and handled in the
        // loop below.
        self.initial_pull(pull_stop.clone());

        loop {
            let e = match event.recv() {
                Ok(e) => e,
                Err(e) => {
                    error!(self.log, "exchange event recv: {}", e);
                    continue;
                }
            };
            match e {
                Event::Admin(AdminEvent::Announce(prefixes)) => {
                    crate::exchange::announce(
                        self.ctx.config.clone(),
                        prefixes,
                        self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    );
                }
                Event::Admin(AdminEvent::Withdraw(prefixes)) => {
                    crate::exchange::withdraw(
                        self.ctx.config.clone(),
                        prefixes,
                        self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    );
                }
                Event::Admin(AdminEvent::Sync) => {
                    if let Err(e) = crate::exchange::pull(
                        self.ctx.clone(),
                        self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_index,
                            "exchange pull: {}",
                            e
                        );
                    }
                }
                Event::Peer(PeerEvent::Push(push)) => {
                    if !push.announce.is_empty() {
                        crate::exchange::announce(
                            self.ctx.config.clone(),
                            push.announce,
                            self.peer,
                            self.ctx.rt.clone(),
                            self.log.clone(),
                        );
                    }
                    if !push.withdraw.is_empty() {
                        crate::exchange::withdraw(
                            self.ctx.config.clone(),
                            push.withdraw,
                            self.peer,
                            self.ctx.rt.clone(),
                            self.log.clone(),
                        );
                    }
                }
                Event::Neighbor(NeighborEvent::Expire) => {
                    exchange_thread.abort();
                    let to_remove =
                        self.ctx.db.remove_nexthop_routes(self.peer);
                    let mut routes: Vec<crate::sys::Route> = Vec::new();
                    for x in &to_remove {
                        let mut r: crate::sys::Route = x.clone().into();
                        r.ifname = self.ctx.config.if_name.clone();
                        routes.push(r);
                    }
                    if let Err(e) = crate::sys::remove_routes(
                        &self.log,
                        &self.ctx.config.dpd,
                        routes,
                        &self.ctx.rt,
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_index,
                            "failed to remove routes: {}",
                            e,
                        );
                    }
                    pull_stop.store(true, Ordering::Relaxed);
                    return (
                        Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        )),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Advertise(addr)) => {
                    self.peer = addr
                }
            }
        }
    }
}
