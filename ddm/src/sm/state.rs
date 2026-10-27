// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Routing state machine implementation. The `Init` -> `Solicit` ->
//! `Exchange` lifecycle drives kernel route programming via [`crate::sys`]
//! and reads interface addressing through `libnet`. This module is
//! illumos-only.

use super::{
    AdminEvent, Event, FsmState, NeighborEvent, PeerEvent, PrefixSet,
    SmContext, SmError, StateMachine,
};
use crate::db::RemovedRoutes;
use crate::sm::{PeerIdentity, RouteAdvertisementAllowances};
use crate::{dbg, discovery, err, exchange, inf, wrn};
use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::{
    PathVector, RackPrefix, RackUpdate, TunnelUpdate, UnderlayUpdate, Update,
};
use libnet::get_ipaddr_info;
use slog::Logger;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::thread::{JoinHandle, sleep, spawn};
use std::time::Duration;

impl StateMachine {
    pub fn run(&mut self) -> Result<(), SmError> {
        let ctx = self.ctx.clone();
        let mut rx = self.rx.take().unwrap();
        let log = self.ctx.log.clone();
        spawn(move || {
            let mut state: Option<Box<dyn State>> =
                Some(Box::new(Init::new(ctx.clone(), log.clone())));
            loop {
                (state, rx) = match &mut state {
                    Some(st) => st.run(rx),
                    None => break,
                }
            }
        });

        Ok(())
    }
}

trait State {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Option<Box<dyn State>>, Receiver<Event>);
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
    ) -> (Option<Box<dyn State>>, Receiver<Event>) {
        self.ctx.iface.transition(FsmState::Init);
        self.ctx.iface.clear_peer();
        loop {
            // Check for shutdown or new peers
            while let Ok(e) = event.try_recv() {
                match e {
                    Event::Admin(AdminEvent::Shutdown) => {
                        return (None, event);
                    }
                    Event::Admin(AdminEvent::NewExternalPeer {
                        aobj_name,
                        tx,
                    }) => {
                        self.ctx.event_channels.insert(aobj_name, tx);
                    }
                    _ => {
                        wrn!(
                            self.log,
                            self.ctx.config.aobj_name,
                            "event unhandled in init state: {e:?}"
                        );
                    }
                }
            }
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
                    sleep(self.ctx.config.ip_addr_wait);
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
                    sleep(self.ctx.config.ip_addr_wait);
                    continue;
                }
            };
            self.ctx.config.if_name.clone_from(&info.ifname);
            self.ctx.config.if_index = info.index as u32;
            self.ctx.config.addr = addr;
            self.ctx
                .iface
                .set_if_info(info.index as u32, info.ifname.clone());
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
            let discovery_stop = match discovery::handler(
                self.ctx.router_id.clone(),
                self.ctx.config.clone(),
                self.ctx.tx.clone(),
                self.ctx.iface.clone(),
                self.ctx.stats.clone(),
                self.ctx.log.clone(),
            ) {
                Ok(stop) => stop,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "failed to start discovery handler: {e}",
                    );
                    sleep(self.ctx.config.solicit_interval);
                    continue;
                }
            };
            self.ctx.discovery_stop = Some(discovery_stop);
            return (
                Some(Box::new(Solicit::new(
                    self.ctx.clone(),
                    self.log.clone(),
                ))),
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
    ) -> (Option<Box<dyn State>>, Receiver<Event>) {
        self.ctx.iface.transition(FsmState::Solicit);
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
                Event::Neighbor(NeighborEvent::Advertise(peer)) => {
                    dbg!(
                        self.log,
                        self.ctx.config.if_name,
                        "transition solicit -> exchange"
                    );
                    return (
                        Some(Box::new(Exchange::new(
                            self.ctx.clone(),
                            peer,
                            self.log.clone(),
                        ))),
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
                        Some(Box::new(Init::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
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
                Event::Admin(AdminEvent::NewExternalPeer { aobj_name, tx }) => {
                    self.ctx.event_channels.insert(aobj_name, tx);
                }
                Event::Admin(AdminEvent::Shutdown) => {
                    if let Some(x) = self.ctx.discovery_stop.as_mut() {
                        x.store(true, Ordering::Relaxed);
                    }
                    return (None, event);
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
    peer: PeerIdentity,
    peer_allowances: RouteAdvertisementAllowances,
    ctx: SmContext,
    log: Logger,
}

impl Exchange {
    fn new(ctx: SmContext, peer: PeerIdentity, log: Logger) -> Self {
        let peer_allowances =
            RouteAdvertisementAllowances::new(ctx.config.kind, peer.kind);
        Self {
            ctx,
            peer,
            peer_allowances,
            log,
        }
    }

    fn initial_pull(&mut self, stop: Arc<AtomicBool>) -> JoinHandle<()> {
        let peer = self.peer.clone();
        let rt = self.ctx.rt.clone();
        let log = self.log.clone();
        let interval = self.ctx.config.solicit_interval;
        let if_name = self.ctx.config.if_name.clone();
        let ctx = self.ctx.clone();

        spawn(move || {
            while let Err(e) =
                crate::exchange::pull(&ctx, &peer, rt.clone(), stop.clone())
            {
                sleep(interval);
                wrn!(log, if_name, "exchange pull: {}", e);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        })
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
                self.ctx.config.addr,
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
        initial_pull: JoinHandle<()>,
    ) {
        // Stop other threads that may update the rib after we clear for expiry.
        pull_stop.store(true, Ordering::Relaxed);
        if let Err(e) = initial_pull.join() {
            err!(
                self.log,
                self.ctx.config.if_name,
                "failed to join initial pull thread: {e:?}",
            );
        }

        exchange_thread.abort();
        self.ctx.iface.clear_peer();

        // compilation barrier. a new RIB table must be handled here.
        let RemovedRoutes {
            underlay: mut to_remove,
            tunnel: to_remove_tnl,
            rack: mut to_remove_rack,
        } = self.ctx.db.remove_nexthop_routes(self.peer.addr);

        // Underlay and rack routes share the underlay forwarding table. Every
        // route via this peer is now gone from both RIB tables, so all of
        // their forwarding entries go.
        let mut routes: Vec<crate::sys::Route> = Vec::new();
        for x in to_remove
            .iter()
            .chain(to_remove_rack.iter().map(|r| &r.route))
        {
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

        dbg!(
            self.log,
            self.ctx.config.if_name,
            "redistributing expire to {} peers",
            self.ctx.event_channels.len()
        );

        // Only send withdraws for expirations that result in a total loss
        // of reachability to a destination for the given path.
        let imported = self.ctx.db.imported();
        dbg!(self.log, self.ctx.config.if_name, "imported: {imported:#?}");
        dbg!(
            self.log,
            self.ctx.config.if_name,
            "to_remove: {to_remove:#?}"
        );
        to_remove.retain(|x| {
            !imported
                .iter()
                .any(|y| y.destination == x.destination && y.path == x.path)
        });
        dbg!(
            self.log,
            self.ctx.config.if_name,
            "to_remove (retained): {to_remove:#?}"
        );

        let underlay = if to_remove.is_empty() {
            None
        } else {
            Some(UnderlayUpdate::withdraw(
                to_remove
                    .into_iter()
                    .map(|x| PathVector {
                        destination: x.destination,
                        path: {
                            let mut ps = x.path;
                            ps.push(self.ctx.router_id.clone());
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
                to_remove_tnl.into_iter().map(Into::into).collect(),
            ))
        };

        // Only send withdraws for expirations that result in a total loss
        // of reachability to a destination for the given path.
        let imported_rack = self.ctx.db.imported_rack();
        dbg!(
            self.log,
            self.ctx.config.if_name,
            "imported_rack: {imported_rack:#?}"
        );
        dbg!(
            self.log,
            self.ctx.config.if_name,
            "to_remove_rack: {to_remove_rack:#?}"
        );
        to_remove_rack.retain(|x| {
            !imported_rack.iter().any(|y| {
                y.multi_rack_join_addr == x.multi_rack_join_addr
                    && y.route.destination == x.route.destination
                    && y.route.path == x.route.path
            })
        });
        dbg!(
            self.log,
            self.ctx.config.if_name,
            "to_remove_rack (retained): {to_remove_rack:#?}"
        );

        let rack = if to_remove_rack.is_empty() {
            None
        } else {
            Some(RackUpdate::withdraw(
                to_remove_rack
                    .into_iter()
                    .map(|x| {
                        let mut rp = RackPrefix::from(x);
                        rp.path_vector.path.push(self.ctx.router_id.clone());
                        rp
                    })
                    .collect(),
            ))
        };

        let push = Update {
            underlay,
            tunnel,
            rack,
        };
        if push.is_empty() {
            return;
        }

        super::send(
            Event::Peer(PeerEvent::Push(push)),
            &mut self.ctx.event_channels,
        );
    }
}

impl State for Exchange {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Option<Box<dyn State>>, Receiver<Event>) {
        self.ctx.iface.transition(FsmState::Exchange);
        let exchange_thread = loop {
            match exchange::handler(
                self.ctx.clone(),
                self.ctx.config.addr,
                self.peer.clone(),
                self.peer_allowances.clone(),
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
        let initial_pull = self.initial_pull(pull_stop.clone());

        if self.ctx.iface.external && self.ctx.first_run {
            self.ctx.first_run = false;
            crate::sm::send(
                Event::Admin(AdminEvent::NewExternalPeer {
                    aobj_name: self.ctx.config.aobj_name.clone(),
                    tx: self.ctx.tx.clone(),
                }),
                &mut self.ctx.event_channels,
            );
        }

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
                    // skip if we aren't allowed to transmit underlay prefixes
                    if !self.peer_allowances.underlay() {
                        continue;
                    }

                    let pv: HashSet<PathVector> = prefixes
                        .iter()
                        .map(|x| PathVector {
                            destination: *x,
                            path: vec![self.ctx.router_id.clone()],
                        })
                        .collect();
                    let Err(e) = crate::exchange::announce_underlay(
                        &self.ctx,
                        self.ctx.config.clone(),
                        pv,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

                    err!(self.log, self.ctx.config.if_name, "announce: {}", e,);
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed announce",
                        self.peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );

                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Announce(PrefixSet::Tunnel(
                    endpoints,
                ))) => {
                    // skip if we aren't allowed to transmit tunnel prefixes
                    if !self.peer_allowances.tunnel() {
                        continue;
                    }

                    let tv: HashSet<TunnelOrigin> = endpoints.clone();
                    let Err(e) = crate::exchange::announce_tunnel(
                        &self.ctx,
                        self.ctx.config.clone(),
                        tv,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

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
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );

                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Announce(PrefixSet::Rack(
                    prefixes,
                ))) => {
                    // skip if we aren't allowed to transmit rack prefixes
                    if !self.peer_allowances.rack() {
                        continue;
                    }

                    let Err(e) = crate::exchange::announce_rack(
                        &self.ctx,
                        self.ctx.config.clone(),
                        prefixes,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

                    err!(
                        self.log,
                        self.ctx.config.if_name,
                        "rack prefix announce: {e}",
                    );
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed rack prefix announce",
                        self.peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );

                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Withdraw(PrefixSet::Underlay(
                    prefixes,
                ))) => {
                    // skip if we aren't allowed to transmit underlay prefixes
                    if !self.peer_allowances.underlay() {
                        continue;
                    }

                    let pv: HashSet<PathVector> = prefixes
                        .iter()
                        .map(|x| PathVector {
                            destination: *x,
                            path: vec![self.ctx.router_id.clone()],
                        })
                        .collect();
                    let Err(e) = crate::exchange::withdraw_underlay(
                        &self.ctx,
                        self.ctx.config.clone(),
                        pv,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

                    err!(self.log, self.ctx.config.if_name, "withdraw: {}", e,);
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed withdraw",
                        self.peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );

                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Withdraw(PrefixSet::Tunnel(
                    endpoints,
                ))) => {
                    // skip if we aren't allowed to transmit tunnel prefixes
                    if !self.peer_allowances.tunnel() {
                        continue;
                    }

                    let tv: HashSet<TunnelOrigin> = endpoints.clone();

                    let Err(e) = crate::exchange::withdraw_tunnel(
                        &self.ctx,
                        self.ctx.config.clone(),
                        tv,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

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
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );

                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Withdraw(PrefixSet::Rack(
                    prefixes,
                ))) => {
                    // skip if we aren't allowed to transmit rack prefixes
                    if !self.peer_allowances.rack() {
                        continue;
                    }

                    let Err(e) = crate::exchange::withdraw_rack(
                        &self.ctx,
                        self.ctx.config.clone(),
                        prefixes,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

                    err!(self.log, self.ctx.config.if_name, "withdraw: {}", e,);
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed withdraw",
                        self.peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );

                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Expire(peer)) => {
                    if self.peer.addr != peer {
                        continue;
                    }

                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "administratively expiring peer {}",
                        peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );
                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Admin(AdminEvent::Sync) => {
                    let rt = self.ctx.rt.clone();
                    if let Err(e) = crate::exchange::pull(
                        &self.ctx,
                        &self.peer,
                        rt,
                        pull_stop.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "exchange pull: {}",
                            e
                        );
                    }
                }
                Event::Admin(AdminEvent::NewExternalPeer { aobj_name, tx }) => {
                    // Send the new peer only the routes learned from our own
                    // peer. Every sibling does the same, so together they send
                    // one copy of the imported tables rather than one each.
                    // Every route class is included; the new peer's Push
                    // handler filters by its own advertisement allowances.
                    //
                    // Sending and registering in this one step keeps our share
                    // consistent: routes we imported before now are in this
                    // push, and later ones reach the new peer through our
                    // Redistribute fan-out once it is registered.
                    let db = &self.ctx.db;
                    let router_id = self.ctx.router_id.clone();
                    let push = Update {
                        underlay: Some(
                            UnderlayUpdate::announce(
                                db.imported_from(self.peer.addr)
                                    .into_iter()
                                    .map(Into::into)
                                    .collect(),
                            )
                            .with_path_element(router_id.clone()),
                        ),
                        tunnel: Some(TunnelUpdate::announce(
                            db.imported_tunnel_from(self.peer.addr)
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                        )),
                        rack: Some(
                            RackUpdate::announce(
                                db.imported_rack_from(self.peer.addr)
                                    .into_iter()
                                    .map(Into::into)
                                    .collect(),
                            )
                            .with_path_element(router_id),
                        ),
                    };
                    if !push.is_empty() {
                        let _ = tx.send(Event::Peer(PeerEvent::Push(push)));
                    }
                    // Register unconditionally, as Init and Solicit do. A
                    // channel whose peer has already shut down is pruned the
                    // first time a fan-out to it fails.
                    self.ctx.event_channels.insert(aobj_name, tx);
                }
                Event::Admin(AdminEvent::Shutdown) => {
                    if let Some(x) = self.ctx.discovery_stop.as_mut() {
                        x.store(true, Ordering::Relaxed);
                    }
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );
                    return (None, event);
                }
                Event::Peer(PeerEvent::Push(update)) => {
                    // A Push carries only learned routes, so the redistribution
                    // allowance decides whether this peer gets any of it.
                    if !self.peer_allowances.redistributed() {
                        continue;
                    }

                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "push to {}: {:#?}",
                        self.peer,
                        update,
                    );

                    let Err(e) = crate::exchange::send_update(
                        &self.ctx,
                        self.ctx.config.clone(),
                        update,
                        &self.peer,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) else {
                        continue;
                    };

                    err!(self.log, self.ctx.config.if_name, "push: {e}");
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to failed push",
                        self.peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );
                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }

                Event::Peer(PeerEvent::Redistribute(mut update)) => {
                    dbg!(
                        self.log,
                        self.ctx.config.if_name,
                        "redistributing update to {} peers",
                        self.ctx.event_channels.len()
                    );
                    update.underlay = update.underlay.map(|u| {
                        let sans_loops = u.break_loops(&self.ctx.router_id);

                        let announce_loop =
                            u.announce.difference(&sans_loops.announce);
                        let withdraw_loop =
                            u.withdraw.difference(&sans_loops.withdraw);

                        for x in announce_loop {
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "loop detected: dropping announcement: {:?}",
                                x,
                            )
                        }
                        for x in withdraw_loop {
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "loop detected: dropping withdraw {:?}",
                                x,
                            )
                        }

                        sans_loops.with_path_element(self.ctx.router_id.clone())
                    });
                    update.rack = update.rack.map(|r| {
                        let sans_loops = r.break_loops(&self.ctx.router_id);
                        for x in r.announce.difference(&sans_loops.announce) {
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "loop detected: dropping rack announcement: {:?}",
                                x,
                            )
                        }
                        sans_loops.with_path_element(self.ctx.router_id.clone())
                    });
                    // Loop breaking can leave nothing to send.
                    if update.is_empty() {
                        continue;
                    }
                    super::send(
                        Event::Peer(PeerEvent::Push(update)),
                        &mut self.ctx.event_channels,
                    );
                }
                Event::Neighbor(NeighborEvent::Expire) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to discovery event",
                        self.peer,
                    );
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );
                    return (
                        Some(Box::new(Solicit::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
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
                    self.expire_peer(
                        &exchange_thread,
                        &pull_stop,
                        initial_pull,
                    );
                    return (
                        Some(Box::new(Init::new(
                            self.ctx.clone(),
                            self.log.clone(),
                        ))),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Advertise(peer)) => {
                    if self.peer != peer {
                        // The peer has changed out from under us. We can't just
                        // overwrite our state and pretend nothing happened,
                        // otherwise we'd be running with partially stale state.
                        // Expire the old peer, then re-enter Exchange with the
                        // new peer and version info.
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "discovered new peer {peer}; restarting Exchange",
                        );
                        self.expire_peer(
                            &exchange_thread,
                            &pull_stop,
                            initial_pull,
                        );
                        return (
                            Some(Box::new(Exchange::new(
                                self.ctx.clone(),
                                peer,
                                self.log.clone(),
                            ))),
                            event,
                        );
                    }
                }
            }
        }
    }
}
