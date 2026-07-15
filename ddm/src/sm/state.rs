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
use crate::{dbg, discovery, err, exchange, inf, wrn};
use ddm_api_types::db::RouterKind;
use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::{PathVector, TunnelUpdate, UnderlayUpdate};
use ddm_protocol::v4::{MulticastPathHop, MulticastPathVector, Update};
use libnet::get_ipaddr_info;
use slog::Logger;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};

use crate::discovery::Version;
use std::net::Ipv6Addr;

/// Cadence for the periodic pull in the [`Exchange`] state. The initial pull
/// is one-shot, so a neighbor that originates routes after we pull it, late
/// multicast group memberships for instance, would otherwise never be
/// imported absent a push from that neighbor. Pulling on this cadence
/// repairs that drift without operator intervention. It matches the
/// multicast sweep reconcile interval so both repair loops converge on the
/// same cadence. Pre-V4 peers are skipped, since their responses carry no
/// multicast half. The exchange loop checks a fixed deadline before
/// receiving another event, so a busy event queue cannot postpone the pull
/// indefinitely.
const EXCHANGE_RESYNC_INTERVAL: Duration = crate::mcast::RECONCILE_INTERVAL;

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
        self.ctx.iface.transition(FsmState::Init);
        self.ctx.iface.clear_peer();
        loop {
            let info = match get_ipaddr_info(&self.ctx.config.aobj_name) {
                Ok(info) => info,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "failed to get IPv6 address for interface {}: {e}",
                        &self.ctx.config.aobj_name,
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
            discovery::handler(
                self.ctx.hostname.clone(),
                self.ctx.config.clone(),
                self.ctx.tx.clone(),
                self.ctx.iface.clone(),
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
        self.ctx.iface.transition(FsmState::Solicit);
        loop {
            let e = match event.recv() {
                Ok(e) => e,
                Err(e) => {
                    err!(
                        self.log,
                        self.ctx.config.if_name,
                        "solicit event recv: {e}",
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

                    // The peer is now established on this link, so wake the
                    // multicast sweep for any of its groups whose import raced
                    // ahead of resolution.
                    crate::mcast::notify_peer_groups(
                        &self.ctx.db,
                        addr,
                        &self.ctx.mcast_notify,
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

struct Exchange {
    peer: Ipv6Addr,
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
                exchange::UpdateMode::Redistribute,
            ) {
                sleep(Duration::from_millis(interval));
                wrn!(log, if_name, "exchange pull: {e}");
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
        });
    }

    fn periodic_pull(&self) {
        // The resync exists to repair multicast drift, and multicast first
        // appears on the wire in V4. An earlier peer's response has no
        // multicast half, so a pull would only replay the full underlay and
        // tunnel tables while holding the route_update lock.
        if self.version < Version::V4 {
            return;
        }
        if let Err(e) = crate::exchange::pull(
            self.ctx.clone(),
            self.peer,
            self.version,
            self.ctx.rt.clone(),
            self.log.clone(),
            exchange::UpdateMode::ImportOnly,
        ) {
            wrn!(
                self.log,
                self.ctx.config.if_name,
                "periodic exchange pull: {e}",
            );
        }
    }

    fn wait_for_exchange_server_to_start(&self) {
        inf!(
            self.log,
            self.ctx.config.if_name,
            "waiting for exchange server to start"
        );
        let interval = 250; // TODO as parameter
        loop {
            match exchange::do_pull_v4(
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
        exchange_handle: &exchange::ExchangeHandle,
        pull_stop: &AtomicBool,
    ) {
        exchange_handle.abort();
        self.ctx.iface.clear_peer();
        self.withdraw_peer_routes(self.peer);
        pull_stop.store(true, Ordering::Relaxed);
    }

    /// Remove all routes imported via `peer`, clean up the forwarding state
    /// derived from them, and, on transit routers, propagate withdraws to the
    /// remaining peers.
    ///
    /// Called on peer expiry and on renumber, where a re-advertisement
    /// carries a new peer address and `peer` is the prior one.
    fn withdraw_peer_routes(&self, peer: Ipv6Addr) {
        // Exchange updates take the same lock. If an old-peer update is
        // already running, cleanup follows it and removes its imports. If
        // cleanup wins, the update subsequently observes the changed peer
        // identity and is discarded.
        let _route_update = mg_common::lock!(self.ctx.iface.route_update);
        let removed = self.ctx.db.remove_nexthop_routes(peer);
        self.redistribute_removed_routes(&removed);
        let crate::db::RemovedNexthopRoutes {
            underlay: to_remove,
            tunnel: to_remove_tnl,
            multicast: to_remove_mcast,
            ..
        } = removed;
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

        // The peer's routes are gone from the imported set, so we notify the
        // multicast sweep of each affected underlay group. The sweep drops the
        // peer's replication membership from DPD.
        crate::mcast::notify_affected_groups(
            to_remove_mcast.iter(),
            &self.ctx.mcast_notify,
        );
    }

    fn redistribute_removed_routes(
        &self,
        removed: &crate::db::RemovedNexthopRoutes,
    ) {
        // If we're a transit router propagate withdraws for the
        // removed routes.
        if self.ctx.config.kind == RouterKind::Transit {
            dbg!(
                self.log,
                self.ctx.config.if_name,
                "redistributing withdraws to {} peers",
                self.ctx.event_channels.len()
            );

            let underlay = (!removed.underlay.is_empty()).then(|| {
                UnderlayUpdate::withdraw(
                    removed
                        .underlay
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
                )
            });

            let tunnel = (!removed.tunnel.is_empty()).then(|| {
                TunnelUpdate::withdraw(
                    removed.tunnel.iter().cloned().map(Into::into).collect(),
                )
            });

            // Downstream peers collapse all paths through us into one route.
            // For each removed origin, either withdraw the final path or
            // refresh the peer with a remaining imported/local path.
            let multicast = if removed.multicast.is_empty() {
                None
            } else {
                let withdrawals: HashSet<_> = removed
                    .multicast
                    .iter()
                    .map(|route| MulticastPathVector {
                        origin: (&route.origin).into(),
                        path: Vec::new(),
                    })
                    .collect();
                let update = crate::exchange::reconcile_multicast_withdrawals(
                    &withdrawals,
                    &removed.mcast_reachability,
                    &MulticastPathHop::new(
                        self.ctx.hostname.clone(),
                        self.ctx.config.addr,
                    ),
                );
                if update.announce.is_empty() && update.withdraw.is_empty() {
                    None
                } else {
                    Some(update)
                }
            };

            let push = Arc::new(Update {
                underlay,
                tunnel,
                multicast,
            });
            for ec in &self.ctx.event_channels {
                if let Err(e) =
                    ec.send(Event::Peer(PeerEvent::Push(Arc::clone(&push))))
                {
                    err!(
                        self.log,
                        self.ctx.config.if_name,
                        "deliver redistributed withdraw: {e}",
                    );
                }
            }
        }
    }
}

impl State for Exchange {
    fn run(
        &mut self,
        event: Receiver<Event>,
    ) -> (Box<dyn State>, Receiver<Event>) {
        self.ctx.iface.transition(FsmState::Exchange);
        let exchange_handle = loop {
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

        let mut resync_deadline = Instant::now() + EXCHANGE_RESYNC_INTERVAL;
        loop {
            if Instant::now() >= resync_deadline {
                self.periodic_pull();
                resync_deadline = Instant::now() + EXCHANGE_RESYNC_INTERVAL;
            }

            let wait =
                resync_deadline.saturating_duration_since(Instant::now());
            let e = match event.recv_timeout(wait) {
                Ok(e) => e,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(e) => {
                    err!(
                        self.log,
                        self.ctx.config.if_name,
                        "exchange event recv: {e}",
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
                            "announce: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed announce",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
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
                            "announce tunnel: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed tunnel announce",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
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
                            "withdraw: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed withdraw",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
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
                            "withdraw tunnel: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed tunnel withdraw",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::AnnounceMulticast(groups)) => {
                    // Build a `MulticastPathVector` for each origin, recording
                    // our hop in the path.
                    let hop = MulticastPathHop::new(
                        self.ctx.hostname.clone(),
                        self.ctx.config.addr,
                    );
                    let path_vectors: HashSet<_> = groups
                        .iter()
                        .map(|origin| {
                            ddm_api_types::exchange::MulticastPathVector {
                                origin: origin.into(),
                                path: vec![hop.clone()],
                            }
                        })
                        .collect();

                    if let Err(e) = crate::exchange::announce_multicast(
                        &self.ctx,
                        self.ctx.config.clone(),
                        path_vectors,
                        self.peer,
                        self.version,
                        self.ctx.rt.clone(),
                        self.log.clone(),
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "announce multicast: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed multicast announce",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::WithdrawMulticast(origins)) => {
                    // The persistent local origins were removed by the
                    // modification that preceded this event. The reachability
                    // snapshot is read here, at processing time, so an
                    // import that raced the admin request is observed and
                    // produces a replacement announcement rather than a
                    // stale final withdrawal. Whenever an imported path to
                    // an origin remains, replace the local announcement with
                    // that path. Otherwise, propagate the final withdrawal.
                    let hop = MulticastPathHop::new(
                        self.ctx.hostname.clone(),
                        self.ctx.config.addr,
                    );
                    let withdrawals: HashSet<_> = origins
                        .iter()
                        .map(|origin| MulticastPathVector {
                            origin: origin.into(),
                            path: Vec::new(),
                        })
                        .collect();
                    let reachability = self.ctx.db.multicast_reachability();
                    let update =
                        crate::exchange::reconcile_multicast_withdrawals(
                            &withdrawals,
                            &reachability,
                            &hop,
                        );

                    if !update.announce.is_empty()
                        && let Err(e) = crate::exchange::announce_multicast(
                            &self.ctx,
                            self.ctx.config.clone(),
                            update.announce,
                            self.peer,
                            self.version,
                            self.ctx.rt.clone(),
                            self.log.clone(),
                        )
                    {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "replace withdrawn multicast path: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed multicast replacement",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
                        return (
                            Box::new(Solicit::new(
                                self.ctx.clone(),
                                self.log.clone(),
                            )),
                            event,
                        );
                    }

                    if !update.withdraw.is_empty()
                        && let Err(e) = crate::exchange::withdraw_multicast(
                            &self.ctx,
                            self.ctx.config.clone(),
                            update.withdraw,
                            self.peer,
                            self.version,
                            self.ctx.rt.clone(),
                            self.log.clone(),
                        )
                    {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "withdraw multicast: {e}",
                        );
                        wrn!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {} due to failed multicast withdraw",
                            self.peer,
                        );
                        self.expire_peer(&exchange_handle, &pull_stop);
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
                        self.expire_peer(&exchange_handle, &pull_stop);
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
                        exchange::UpdateMode::Redistribute,
                    ) {
                        err!(
                            self.log,
                            self.ctx.config.if_name,
                            "exchange pull: {e}",
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
                    let update = Arc::try_unwrap(update)
                        .unwrap_or_else(|arc| (*arc).clone());
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
                                "announce: {e}",
                            );
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "expiring peer {} due to failed announce",
                                self.peer,
                            );
                            self.expire_peer(&exchange_handle, &pull_stop);
                            return (
                                Box::new(Solicit::new(
                                    self.ctx.clone(),
                                    self.log.clone(),
                                )),
                                event,
                            );
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
                                "withdraw: {e}",
                            );
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "expiring peer {} due to failed withdraw",
                                self.peer,
                            );
                            self.expire_peer(&exchange_handle, &pull_stop);
                            return (
                                Box::new(Solicit::new(
                                    self.ctx.clone(),
                                    self.log.clone(),
                                )),
                                event,
                            );
                        }
                    }

                    if let Some(push) = update.multicast {
                        if !push.announce.is_empty()
                            && let Err(e) = crate::exchange::announce_multicast(
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
                                "announce multicast: {e}",
                            );
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "expiring peer {} due to failed multicast announce",
                                self.peer,
                            );
                            self.expire_peer(&exchange_handle, &pull_stop);
                            return (
                                Box::new(Solicit::new(
                                    self.ctx.clone(),
                                    self.log.clone(),
                                )),
                                event,
                            );
                        }

                        if !push.withdraw.is_empty()
                            && let Err(e) = crate::exchange::withdraw_multicast(
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
                                "withdraw multicast: {e}",
                            );
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "expiring peer {} due to failed multicast withdraw",
                                self.peer,
                            );
                            self.expire_peer(&exchange_handle, &pull_stop);
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
                Event::Neighbor(NeighborEvent::Expire) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "expiring peer {} due to discovery event",
                        self.peer,
                    );
                    self.expire_peer(&exchange_handle, &pull_stop);
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
                    self.expire_peer(&exchange_handle, &pull_stop);
                    return (
                        Box::new(Init::new(self.ctx.clone(), self.log.clone())),
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    if addr != self.peer {
                        // A re-advertisement carrying a new address renumbers
                        // the peer. Expiry removes routes keyed on the
                        // current address only, so routes under the prior
                        // address would otherwise persist indefinitely.
                        // Withdraw them as if that address expired.
                        inf!(
                            self.log,
                            self.ctx.config.if_name,
                            "peer renumbered from {} to {addr}",
                            self.peer,
                        );
                        // Rebind the running exchange handler so that
                        // pushes arriving under the new address cannot
                        // recreate routes keyed by the prior peer after
                        // cleanup.
                        exchange_handle.renumber_peer(addr);
                        self.withdraw_peer_routes(self.peer);
                    }
                    self.peer = addr;
                    self.version = version;
                    // Wake the multicast sweep for the peer's groups under
                    // the advertised address.
                    crate::mcast::notify_peer_groups(
                        &self.ctx.db,
                        addr,
                        &self.ctx.mcast_notify,
                    );
                }
            }
        }
    }
}
