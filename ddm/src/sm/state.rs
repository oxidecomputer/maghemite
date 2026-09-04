// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Routing state machine implementation. The `Init` -> `Solicit` ->
//! `Exchange` lifecycle drives kernel route programming via [`crate::sys`]
//! and resolves interface addressing through `libnet`. This module is
//! illumos-only.

use super::{
    AdminEvent, Event, FsmState, NeighborEvent, PeerEvent, PrefixSet,
    SmContext, StateMachine, Stop,
};
use crate::{dbg, discovery, err, exchange, inf, wrn};
use ddm_api_types::db::RouterKind;
use ddm_protocol::v3::{PathVector, TunnelUpdate, UnderlayUpdate, Update};
use slog::Logger;
use std::collections::HashSet;
use std::sync::mpsc::Receiver;
use std::thread::{JoinHandle, spawn};
use std::time::Duration;

use crate::discovery::Version;
use ddm_api_types::net::TunnelOrigin;
use std::net::Ipv6Addr;

impl StateMachine {
    pub fn spawn(ctx: SmContext, mut rx: Receiver<Event>) -> Self {
        let stop = Stop::default();
        let thread_ctx = ctx.clone();
        let log = ctx.log.clone();
        let thread_stop = stop.clone();
        let thread = spawn(move || {
            let mut state: Box<dyn State> = Box::new(Init::new(
                thread_ctx.clone(),
                log.clone(),
                thread_stop,
            ));
            while let Step::Next(next, event) = state.run(rx) {
                state = next;
                rx = event;
            }
        });
        Self {
            ctx,
            thread: Some(thread),
            stop,
        }
    }

    pub fn signal_stop(&self) {
        self.stop.set();
        let _ = self.ctx.tx.send(Event::Shutdown);
    }

    pub fn join(self) {
        if let Some(thread) = self.thread
            && thread.join().is_err()
        {
            err!(self.ctx.log, self.ctx.config.if_name, "fsm thread panicked");
        }
    }
}

enum Step {
    Next(Box<dyn State>, Receiver<Event>),
    Stopped,
}

trait State {
    fn run(&mut self, event: Receiver<Event>) -> Step;
}

fn sweep_interface(ctx: &SmContext, log: &Logger) {
    let stale = ctx.db.remove_interface_routes(&ctx.config.if_name);
    if stale.is_empty() {
        return;
    }
    wrn!(
        log,
        ctx.config.if_name,
        "removing {} stale routes at shutdown",
        stale.len()
    );
    let routes = stale
        .iter()
        .map(|route| {
            let mut route: crate::sys::Route = route.clone().into();
            route.ifname.clone_from(&ctx.config.if_name);
            route
        })
        .collect();
    crate::sys::remove_underlay_routes(
        log,
        &ctx.config.if_name,
        &ctx.config.dpd,
        routes,
        &ctx.rt,
    );
}

struct Init {
    ctx: SmContext,
    log: Logger,
    stop: Stop,
}

impl Init {
    fn new(ctx: SmContext, log: Logger, stop: Stop) -> Self {
        Self { ctx, log, stop }
    }
}

impl State for Init {
    fn run(&mut self, event: Receiver<Event>) -> Step {
        self.ctx.iface.transition(FsmState::Init);
        self.ctx.iface.clear_peer();
        loop {
            let (if_index, addr) = match crate::sys::link_local_addr(
                &self.log,
                &self.ctx.config.if_name,
            ) {
                Ok(found) => found,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "failed to get IPv6 link-local address: {e}",
                    );
                    if self.stop.wait(Duration::from_millis(
                        self.ctx.config.ip_addr_wait,
                    )) {
                        sweep_interface(&self.ctx, &self.log);
                        return Step::Stopped;
                    }
                    continue;
                }
            };
            self.ctx.config.if_index = if_index;
            self.ctx.config.addr = addr;
            self.ctx.iface.set_if_info(
                if_index,
                self.ctx.config.if_name.clone(),
                addr,
            );
            inf!(
                self.log,
                self.ctx.config.if_name,
                "sm initialized with addr {} on if {} index {}",
                &addr,
                &self.ctx.config.if_name,
                if_index,
            );

            // Now that we have an ip address to run discovery on, start the
            // discovery handler and jump into the solicit state.
            let discovery = discovery::handler(
                self.ctx.hostname.clone(),
                self.ctx.config.clone(),
                self.ctx.tx.clone(),
                self.ctx.iface.clone(),
                self.ctx.stats.clone(),
                self.ctx.log.clone(),
            )
            .unwrap(); // TODO unwrap
            return Step::Next(
                Box::new(Solicit::new(
                    self.ctx.clone(),
                    self.log.clone(),
                    self.stop.clone(),
                    Some(discovery),
                )),
                event,
            );
        }
    }
}

struct Solicit {
    ctx: SmContext,
    log: Logger,
    stop: Stop,
    discovery: Option<discovery::DiscoveryHandle>,
}

impl Solicit {
    fn new(
        ctx: SmContext,
        log: Logger,
        stop: Stop,
        discovery: Option<discovery::DiscoveryHandle>,
    ) -> Self {
        Self {
            ctx,
            log,
            stop,
            discovery,
        }
    }

    fn teardown(&mut self) -> Step {
        sweep_interface(&self.ctx, &self.log);
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown();
        }
        Step::Stopped
    }
}

impl State for Solicit {
    fn run(&mut self, event: Receiver<Event>) -> Step {
        self.ctx.iface.transition(FsmState::Solicit);
        loop {
            if self.stop.is_set() {
                return self.teardown();
            }
            let e = match event.recv() {
                Ok(e) => e,
                Err(_) => return self.teardown(),
            };
            match e {
                Event::Shutdown => return self.teardown(),
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    dbg!(
                        self.log,
                        self.ctx.config.if_name,
                        "transition solicit -> exchange"
                    );
                    return Step::Next(
                        Box::new(Exchange::new(
                            self.ctx.clone(),
                            addr,
                            version,
                            self.log.clone(),
                            self.stop.clone(),
                            self.discovery.take(),
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
                    if let Some(discovery) = self.discovery.take() {
                        discovery.shutdown();
                    }
                    return Step::Next(
                        Box::new(Init::new(
                            self.ctx.clone(),
                            self.log.clone(),
                            self.stop.clone(),
                        )),
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

struct Exchange {
    peer: Ipv6Addr,
    version: Version,
    ctx: SmContext,
    log: Logger,
    stop: Stop,
    discovery: Option<discovery::DiscoveryHandle>,
}

impl Exchange {
    fn new(
        ctx: SmContext,
        peer: Ipv6Addr,
        version: Version,
        log: Logger,
        stop: Stop,
        discovery: Option<discovery::DiscoveryHandle>,
    ) -> Self {
        Self {
            ctx,
            peer,
            version,
            log,
            stop,
            discovery,
        }
    }

    fn initial_pull(&self, stop: Stop) -> JoinHandle<()> {
        let ctx = self.ctx.clone();
        let peer = self.peer;
        let version = self.version;
        let rt = self.ctx.rt.clone();
        let log = self.log.clone();
        let interval = self.ctx.config.solicit_interval;
        let if_name = self.ctx.config.if_name.clone();

        spawn(move || {
            loop {
                if stop.is_set() {
                    break;
                }
                match crate::exchange::pull(
                    ctx.clone(),
                    peer,
                    version,
                    rt.clone(),
                    log.clone(),
                ) {
                    Ok(()) => break,
                    Err(e) => wrn!(log, if_name, "exchange pull: {}", e),
                }
                if stop.wait(Duration::from_millis(interval)) {
                    break;
                }
            }
        })
    }

    fn wait_for_exchange_server_to_start(&self) -> bool {
        inf!(
            self.log,
            self.ctx.config.if_name,
            "waiting for exchange server to start"
        );
        let interval = Duration::from_millis(250); // TODO as parameter
        loop {
            match exchange::do_pull(
                &self.ctx,
                &self.ctx.config.addr,
                &self.ctx.rt,
            ) {
                Ok(_) => return true,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "exchange server not started: {e}",
                    );
                    if self.stop.wait(interval) {
                        return false;
                    }
                }
            }
        }
    }

    fn close_session(&mut self, mut session: Session) {
        session.pull_stop.set();
        if let Some(thread) = session.pull_thread.take()
            && thread.join().is_err()
        {
            err!(
                self.log,
                self.ctx.config.if_name,
                "initial pull thread panicked"
            );
        }
        if let Some(server) = session.server.take() {
            server.close(&self.ctx.rt, &self.log, &self.ctx.config.if_name);
        }

        let (to_remove, to_remove_tnl) = self
            .ctx
            .db
            .remove_peer_routes(self.peer, &self.ctx.config.if_name);
        let routes = to_remove
            .iter()
            .map(|route| {
                let mut route: crate::sys::Route = route.clone().into();
                route.ifname.clone_from(&self.ctx.config.if_name);
                route
            })
            .collect();
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

        if self.ctx.config.kind == RouterKind::Transit {
            dbg!(
                self.log,
                self.ctx.config.if_name,
                "redistributing expire to {} peers",
                self.ctx.peer_channels().len()
            );
            let underlay = if to_remove.is_empty() {
                None
            } else {
                Some(UnderlayUpdate::withdraw(
                    to_remove
                        .iter()
                        .map(|route| PathVector {
                            destination: route.destination,
                            path: {
                                let mut path = route.path.clone();
                                path.push(self.ctx.hostname.clone());
                                path
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
            for (name, channel) in self.ctx.peer_channels() {
                if let Err(e) =
                    channel.send(Event::Peer(PeerEvent::Push(push.clone())))
                {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "push to {name}: {e}"
                    );
                }
            }
        }
        self.ctx.iface.clear_peer();
    }

    fn teardown(&mut self, session: Option<Session>) -> Step {
        if let Some(session) = session {
            self.close_session(session);
        }
        sweep_interface(&self.ctx, &self.log);
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown();
        }
        Step::Stopped
    }

    fn transition_to_solicit(
        &mut self,
        session: Session,
        event: Receiver<Event>,
    ) -> Step {
        self.close_session(session);
        Step::Next(
            Box::new(Solicit::new(
                self.ctx.clone(),
                self.log.clone(),
                self.stop.clone(),
                self.discovery.take(),
            )),
            event,
        )
    }

    fn transition_to_init(
        &mut self,
        session: Session,
        event: Receiver<Event>,
    ) -> Step {
        self.close_session(session);
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown();
        }
        Step::Next(
            Box::new(Init::new(
                self.ctx.clone(),
                self.log.clone(),
                self.stop.clone(),
            )),
            event,
        )
    }
}

struct Session {
    server: Option<exchange::ExchangeServer>,
    pull_stop: Stop,
    pull_thread: Option<JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.pull_stop.set();
    }
}

impl State for Exchange {
    fn run(&mut self, event: Receiver<Event>) -> Step {
        self.ctx.iface.transition(FsmState::Exchange);
        if self.stop.is_set() {
            return self.teardown(None);
        }
        let server = loop {
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
                    if self.stop.wait(Duration::from_secs(1)) {
                        return self.teardown(None);
                    }
                    continue;
                }
            }
        };

        if !self.wait_for_exchange_server_to_start() {
            server.close(&self.ctx.rt, &self.log, &self.ctx.config.if_name);
            return self.teardown(None);
        }

        let pull_stop = Stop::default();

        // Do an initial pull, in the event that exchange events are fired while
        // this pull is taking place, they will be queued and handled in the
        // loop below.
        let pull_thread = self.initial_pull(pull_stop.clone());
        let session = Session {
            server: Some(server),
            pull_stop,
            pull_thread: Some(pull_thread),
        };

        loop {
            if self.stop.is_set() {
                return self.teardown(Some(session));
            }
            let e = match event.recv() {
                Ok(e) => e,
                Err(_) => return self.teardown(Some(session)),
            };
            match e {
                Event::Shutdown => return self.teardown(Some(session)),
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
                        return self.transition_to_solicit(session, event);
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
                        return self.transition_to_solicit(session, event);
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
                        return self.transition_to_solicit(session, event);
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
                        return self.transition_to_solicit(session, event);
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
                        return self.transition_to_solicit(session, event);
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
                Event::Peer(PeerEvent::Push(update)) => {
                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "push to {}: {:#?}",
                        self.peer,
                        update,
                    );
                    if let Some(push) = update.underlay {
                        if !push.announce.is_empty()
                            && let Err(e) = crate::exchange::announce_underlay(
                                &self.ctx,
                                self.ctx.config.clone(),
                                push.announce,
                                self.peer,
                                self.version,
                                self.ctx.rt.clone(),
                                self.log.clone(),
                            )
                        {
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
                            return self.transition_to_solicit(session, event);
                        }
                        if !push.withdraw.is_empty()
                            && let Err(e) = crate::exchange::withdraw_underlay(
                                &self.ctx,
                                self.ctx.config.clone(),
                                push.withdraw,
                                self.peer,
                                self.version,
                                self.ctx.rt.clone(),
                                self.log.clone(),
                            )
                        {
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
                            return self.transition_to_solicit(session, event);
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
                    return self.transition_to_solicit(session, event);
                }
                Event::Neighbor(NeighborEvent::SolicitFail) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed solicit",
                        self.peer,
                    );
                    return self.transition_to_init(session, event);
                }
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    self.peer = addr;
                    self.version = version;
                }
            }
        }
    }
}
