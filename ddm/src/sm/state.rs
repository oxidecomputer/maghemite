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
use crate::discovery::Version;
use crate::{dbg, discovery, err, exchange, inf, wrn};
use ddm_api_types::db::RouterKind;
use ddm_api_types::net::TunnelOrigin;
use ddm_protocol::v3::{PathVector, TunnelUpdate, UnderlayUpdate, Update};
use libnet::get_ipaddr_info;
use slog::Logger;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::{JoinHandle, park_timeout, sleep, spawn};
use std::time::{Duration, Instant};

/// The session's pull worker and its control flags.
///
/// A thread per session runs the initial pull, with its retries, and then
/// parks until another pull is requested. Requests made while a pull is
/// running collapse into one follow-up pull, meaning that no two pulls
/// can overlap and that no thread is spawned per request.
///
/// Setting `stop` ends the worker. The same flag identifies the session in
/// [`PeerEvent::PullFailed`].
struct PullWorker {
    stop: Arc<AtomicBool>,
    requested: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl PullWorker {
    /// Ask the worker to pull again. If a pull is already in progress the
    /// request waits for it to finish, while repeated requests collapse into
    /// one pull.
    fn request(&self) {
        self.requested.store(true, Ordering::Relaxed);
        self.thread.thread().unpark();
    }

    /// Stop the worker and wait for it to exit.
    ///
    /// Nothing writes routes for this peer after the caller cleans up.
    fn stop(self) -> std::thread::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.thread().unpark();
        self.thread.join()
    }
}

/// Requests expiry if the pull worker unwinds.
///
/// Otherwise, a panic mid-import would leave the session up with a
/// half-applied snapshot.
struct ExpireOnPanic<'a> {
    tx: &'a Sender<Event>,
    session: &'a Arc<AtomicBool>,
    peer: Ipv6Addr,
    log: &'a Logger,
    if_name: &'a str,
}

impl Drop for ExpireOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            request_expiry(
                self.tx,
                self.session.clone(),
                self.peer,
                self.log,
                self.if_name,
            );
        }
    }
}

fn request_expiry(
    tx: &Sender<Event>,
    session: Arc<AtomicBool>,
    peer: Ipv6Addr,
    log: &Logger,
    if_name: &str,
) {
    if tx
        .send(Event::Peer(PeerEvent::PullFailed { session, peer }))
        .is_err()
    {
        err!(log, if_name, "failed to request expiry of {peer}");
    }
}

/// Where the exchange state transitions to once a peer is expired.
enum Next {
    Solicit,
    Init,
    Shutdown,
}

/// Run a session's pulls until `stop` is set.
///
/// `pull` performs a single attempt, and `expire` asks the state machine to
/// expire the peer.
///
/// `retry_initial_pull` handles the retry and backoff for the initial pull. A
/// requested pull runs once: a persistent HTTP status means the peer no
/// longer serves the negotiated exchange, and the worker requests expiry,
/// while transport and decode errors are left to the next request.
fn run_pull_worker(
    mut pull: impl FnMut() -> Result<(), exchange::ExchangeError>,
    expire: impl Fn(),
    stop: &AtomicBool,
    requested: &AtomicBool,
    interval: Duration,
    log: &Logger,
    if_name: &str,
) {
    if retry_initial_pull(&mut pull, &expire, stop, interval, log, if_name)
        != PullOutcome::Imported
    {
        return;
    }

    while wait_for_request(stop, requested) {
        if pull_once(&mut pull, log, if_name) && !stop.load(Ordering::Relaxed) {
            expire();
            return;
        }
    }
}

/// Park until a pull is requested or the worker is stopped.
///
/// Returns `false` when `stop` is set.
fn wait_for_request(stop: &AtomicBool, requested: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        if requested.swap(false, Ordering::Relaxed) {
            return true;
        }
        std::thread::park();
    }
}

/// Run a requested pull, returning whether the peer must be expired.
///
/// Transport and decode errors wait for another request. A persistent HTTP
/// error requests peer expiry directly.
fn pull_once(
    pull: &mut impl FnMut() -> Result<(), exchange::ExchangeError>,
    log: &Logger,
    if_name: &str,
) -> bool {
    match pull() {
        Ok(()) => false,
        Err(ref e) if e.is_transient() => {
            wrn!(log, if_name, "exchange pull: {e}");
            false
        }
        Err(exchange::ExchangeError::SerdeJson(e)) => {
            err!(log, if_name, "exchange pull: json error: {e}");
            false
        }
        Err(e) => {
            err!(log, if_name, "exchange pull: {e}");
            true
        }
    }
}

/// The outcome of an initial pull from a peer.
#[derive(Debug, PartialEq, Eq)]
enum PullOutcome {
    /// The peer's routes were pulled and imported.
    Imported,
    /// The exchange was shut down before a pull succeeded.
    Stopped,
    /// A persistent HTTP status stops retries and triggers peer expiry.
    ///
    /// Expiry returns the session to rediscovery.
    Expired,
}

fn is_current_session(
    session: &Arc<AtomicBool>,
    peer: Ipv6Addr,
    pull_stop: &Arc<AtomicBool>,
    current_peer: Ipv6Addr,
) -> bool {
    Arc::ptr_eq(session, pull_stop) && peer == current_peer
}

/// The max cap on decode backoff timing, unless the solicit interval is set
/// to be longer.
///
/// Decode errors follow a back off policy instead of expiring the peer outright
/// in order to preserve routes maintained by push updates.
const MAX_DECODE_BACKOFF: Duration = Duration::from_secs(60);

fn next_decode_backoff(curr: Duration, interval: Duration) -> Duration {
    (curr * 2).min(MAX_DECODE_BACKOFF).max(interval)
}

fn retry_initial_pull(
    mut pull: impl FnMut() -> Result<(), exchange::ExchangeError>,
    expire: impl FnOnce(),
    stop: &AtomicBool,
    interval: Duration,
    log: &Logger,
    if_name: &str,
) -> PullOutcome {
    let mut decode_backoff = interval;
    loop {
        let e = match pull() {
            Ok(()) => return PullOutcome::Imported,
            Err(e) => e,
        };

        if stop.load(Ordering::Relaxed) {
            return PullOutcome::Stopped;
        }

        let wait = match e {
            ref e if e.is_transient() => {
                wrn!(log, if_name, "exchange pull: {e}");
                interval
            }
            exchange::ExchangeError::SerdeJson(ref e) => {
                let wait = decode_backoff;
                err!(
                    log,
                    if_name,
                    "exchange pull: initial sync incomplete, retrying in \
                     {wait:?}: json error: {e}"
                );
                decode_backoff = next_decode_backoff(decode_backoff, interval);
                wait
            }
            e => {
                err!(log, if_name, "exchange pull: {e}");
                expire();
                return PullOutcome::Expired;
            }
        };

        // `expire_peer` sets `stop` and unparks this thread before joining it
        // and removing routes.
        //
        // If `park_timeout` returns before the deadline without `stop` set,
        // the loop parks again for the time remaining, and the backoff still
        // holds.
        let wait_started = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            let remaining = wait.saturating_sub(wait_started.elapsed());
            if remaining.is_zero() {
                break;
            }
            park_timeout(remaining);
        }

        if stop.load(Ordering::Relaxed) {
            return PullOutcome::Stopped;
        }
    }
}

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

type Transition = (Option<Box<dyn State>>, Receiver<Event>);

trait State {
    fn run(&mut self, event: Receiver<Event>) -> Transition;
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
    fn run(&mut self, event: Receiver<Event>) -> Transition {
        self.ctx.iface.transition(FsmState::Init);
        self.ctx.iface.clear_peer();
        loop {
            // Check for shutdown or new peers
            while let Ok(e) = event.try_recv() {
                match e {
                    Event::Admin(AdminEvent::Shutdown) => {
                        return (None, event);
                    }
                    Event::Admin(AdminEvent::NewExternalPeer(tx)) => {
                        self.ctx.event_channels.push(tx);
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
    fn run(&mut self, event: Receiver<Event>) -> Transition {
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
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    dbg!(
                        self.log,
                        self.ctx.config.if_name,
                        "transition solicit -> exchange"
                    );
                    return (
                        Some(Box::new(Exchange::new(
                            self.ctx.clone(),
                            addr,
                            version,
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
                Event::Admin(AdminEvent::NewExternalPeer(tx)) => {
                    self.ctx.event_channels.push(tx);
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

    fn pull_log(&self) -> Logger {
        self.log.new(slog::o!(
            "peer" => self.peer.to_string(),
            "version" => format!("{:?}", self.version),
        ))
    }

    fn start_pull_worker(&self) -> PullWorker {
        let stop = Arc::new(AtomicBool::new(false));
        let requested = Arc::new(AtomicBool::new(false));
        let peer = self.peer;
        let version = self.version;
        let rt = self.ctx.rt.clone();
        let log = self.pull_log();
        let interval = self.ctx.config.solicit_interval;
        let ctx = self.ctx.clone();

        let thread = {
            let stop = stop.clone();
            let requested = requested.clone();
            std::thread::Builder::new()
                .name(format!("ddm-pull-{}", self.ctx.config.if_name))
                .spawn(move || {
                    let if_name = &ctx.config.if_name;
                    let _expire_on_panic = ExpireOnPanic {
                        tx: &ctx.tx,
                        session: &stop,
                        peer,
                        log: &log,
                        if_name,
                    };
                    run_pull_worker(
                        || {
                            crate::exchange::pull(
                                &ctx,
                                peer,
                                version,
                                rt.clone(),
                                stop.clone(),
                            )
                        },
                        || {
                            request_expiry(
                                &ctx.tx,
                                stop.clone(),
                                peer,
                                &log,
                                if_name,
                            )
                        },
                        &stop,
                        &requested,
                        interval,
                        &log,
                        &ctx.config.if_name,
                    );
                })
                .expect("spawn ddm pull worker")
        };

        PullWorker {
            stop,
            requested,
            thread,
        }
    }

    fn stop_pull_worker(&self, pull_worker: PullWorker) {
        if let Err(e) = pull_worker.stop() {
            err!(
                self.log,
                self.ctx.config.if_name,
                "failed to join pull worker: {e:?}",
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
            match exchange::do_pull(
                &self.ctx,
                &self.ctx.config.addr,
                &self.ctx.rt,
            ) {
                Ok(_) | Err(exchange::ExchangeError::Status(_)) => break,
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

    fn expire_and_transition(
        &mut self,
        next: Next,
        exchange_thread: &tokio::task::JoinHandle<()>,
        pull_worker: PullWorker,
        event: Receiver<Event>,
    ) -> Transition {
        self.expire_peer(exchange_thread, pull_worker);

        let next: Option<Box<dyn State>> = match next {
            Next::Solicit => {
                Some(Box::new(Solicit::new(self.ctx.clone(), self.log.clone())))
            }
            Next::Init => {
                Some(Box::new(Init::new(self.ctx.clone(), self.log.clone())))
            }
            Next::Shutdown => None,
        };
        (next, event)
    }

    fn expire_peer(
        &mut self,
        exchange_thread: &tokio::task::JoinHandle<()>,
        pull_worker: PullWorker,
    ) {
        // Stop other threads that may update the rib after we clear for expiry.
        self.stop_pull_worker(pull_worker);

        exchange_thread.abort();
        self.ctx.iface.clear_peer();
        let (mut to_remove, to_remove_tnl) =
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
                        .iter()
                        .map(|x| PathVector {
                            destination: x.destination,
                            path: {
                                let mut ps = x.path.clone();
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
                    to_remove_tnl.iter().cloned().map(Into::into).collect(),
                ))
            };

            let push = Update { underlay, tunnel };
            super::send(
                Event::Peer(PeerEvent::Push(push.clone())),
                &mut self.ctx.event_channels,
            );
        }
    }
}

impl State for Exchange {
    fn run(&mut self, event: Receiver<Event>) -> Transition {
        self.ctx.iface.transition(FsmState::Exchange);
        let handler_peer = self.peer;
        let exchange_thread = loop {
            match exchange::handler(
                self.ctx.clone(),
                self.ctx.config.addr,
                handler_peer,
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

        // Do an initial pull, in the event that exchange events are fired while
        // this pull is taking place, they will be queued and handled in the
        // loop below.
        let mut pull_worker = self.start_pull_worker();

        if self.ctx.iface.external && self.ctx.first_run {
            self.ctx.first_run = false;
            crate::sm::send(
                Event::Admin(AdminEvent::NewExternalPeer(self.ctx.tx.clone())),
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
                    let pv: HashSet<PathVector> = prefixes
                        .iter()
                        .map(|x| PathVector {
                            destination: *x,
                            path: vec![self.ctx.router_id.clone()],
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
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
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
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
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
                            path: vec![self.ctx.router_id.clone()],
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
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
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
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::Expire(peer)) => {
                    if self.peer == peer {
                        inf!(
                            self.log,
                            self.ctx.config.if_name,
                            "expiring peer {peer} on request",
                        );
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
                            event,
                        );
                    }
                }
                Event::Peer(PeerEvent::PullFailed { session, peer }) => {
                    if !is_current_session(
                        &session,
                        peer,
                        &pull_worker.stop,
                        self.peer,
                    ) {
                        dbg!(
                            self.log,
                            self.ctx.config.if_name,
                            "ignoring pull failure from a prior session",
                        );
                        continue;
                    }
                    return self.expire_and_transition(
                        Next::Solicit,
                        &exchange_thread,
                        pull_worker,
                        event,
                    );
                }
                Event::Admin(AdminEvent::Sync) => {
                    pull_worker.request();
                }
                Event::Admin(AdminEvent::NewExternalPeer(tx)) => {
                    if tx
                        .send(Event::Peer(PeerEvent::Push(Update {
                            underlay: Some(
                                UnderlayUpdate {
                                    announce: self
                                        .ctx
                                        .db
                                        .imported()
                                        .into_iter()
                                        .map(Into::into)
                                        .collect(),
                                    withdraw: HashSet::default(),
                                }
                                .with_path_element(self.ctx.router_id.clone()),
                            ),
                            tunnel: None,
                        })))
                        .is_ok()
                    {
                        self.ctx.event_channels.push(tx.clone());
                    }
                }
                Event::Admin(AdminEvent::Shutdown) => {
                    if let Some(x) = self.ctx.discovery_stop.as_mut() {
                        x.store(true, Ordering::Relaxed);
                    }
                    return self.expire_and_transition(
                        Next::Shutdown,
                        &exchange_thread,
                        pull_worker,
                        event,
                    );
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
                            return self.expire_and_transition(
                                Next::Solicit,
                                &exchange_thread,
                                pull_worker,
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
                                "withdraw: {}",
                                e,
                            );
                            wrn!(
                                self.log,
                                self.ctx.config.if_name,
                                "expiring peer {} due to failed withdraw",
                                self.peer,
                            );
                            return self.expire_and_transition(
                                Next::Solicit,
                                &exchange_thread,
                                pull_worker,
                                event,
                            );
                        }
                    }
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
                    return self.expire_and_transition(
                        Next::Solicit,
                        &exchange_thread,
                        pull_worker,
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
                    return self.expire_and_transition(
                        Next::Init,
                        &exchange_thread,
                        pull_worker,
                        event,
                    );
                }
                Event::Neighbor(NeighborEvent::Advertise((addr, version))) => {
                    if addr != self.peer {
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
                            event,
                        );
                    }
                    if version == self.version {
                        continue;
                    }
                    let prior_version = self.version;
                    self.version = version;

                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "peer {addr} {prior_version:?} -> {version:?}, \
                         restarting pulls",
                    );

                    // Any pull still running under the prior version must
                    // stop before a new one starts.
                    self.stop_pull_worker(pull_worker);
                    pull_worker = self.start_pull_worker();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExpireOnPanic, MAX_DECODE_BACKOFF, PullOutcome, PullWorker,
        is_current_session, next_decode_backoff, retry_initial_pull,
        run_pull_worker,
    };
    use crate::exchange::ExchangeError;
    use crate::sm::{Event, PeerEvent};
    use hyper::StatusCode;
    use slog::{Discard, Logger, o};
    use std::collections::VecDeque;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::channel;
    use std::time::Duration;

    fn run(
        results: Vec<Result<(), ExchangeError>>,
        stop: &AtomicBool,
    ) -> (PullOutcome, usize, usize) {
        let log = Logger::root(Discard, o!());
        let mut results: VecDeque<_> = results.into();
        let mut pulls = 0;
        let mut expiries = 0;
        let outcome = retry_initial_pull(
            || {
                pulls += 1;
                results.pop_front().expect("pull called too many times")
            },
            || expiries += 1,
            stop,
            Duration::ZERO,
            &log,
            "test0",
        );
        (outcome, pulls, expiries)
    }

    fn status(code: StatusCode) -> Result<(), ExchangeError> {
        Err(ExchangeError::Status(code))
    }

    fn decode_error() -> Result<(), ExchangeError> {
        Err(ExchangeError::SerdeJson(
            serde_json::from_str::<u32>("not json").unwrap_err(),
        ))
    }

    fn io_error() -> Result<(), ExchangeError> {
        Err(ExchangeError::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )))
    }

    #[test]
    fn first_pull_succeeds() {
        let stop = AtomicBool::new(false);
        assert_eq!(run(vec![Ok(())], &stop), (PullOutcome::Imported, 1, 0));
    }

    #[test]
    fn transient_errors_retry_until_success() {
        let stop = AtomicBool::new(false);
        let results = vec![
            status(StatusCode::SERVICE_UNAVAILABLE),
            io_error(),
            status(StatusCode::TOO_MANY_REQUESTS),
            Ok(()),
        ];
        assert_eq!(run(results, &stop), (PullOutcome::Imported, 4, 0));
    }

    #[test]
    fn decode_errors_retry_without_expiry() {
        let stop = AtomicBool::new(false);
        let results = vec![decode_error(), decode_error(), Ok(())];
        assert_eq!(run(results, &stop), (PullOutcome::Imported, 3, 0));
    }

    #[test]
    fn client_error_expires_once() {
        let stop = AtomicBool::new(false);
        assert_eq!(
            run(vec![status(StatusCode::NOT_FOUND)], &stop),
            (PullOutcome::Expired, 1, 1),
        );
    }

    #[test]
    fn persistent_status_after_transient_expires() {
        let stop = AtomicBool::new(false);
        let results = vec![
            status(StatusCode::BAD_GATEWAY),
            status(StatusCode::BAD_REQUEST),
        ];
        assert_eq!(run(results, &stop), (PullOutcome::Expired, 2, 1));
    }

    #[test]
    fn stop_prevents_expiry() {
        let stop = AtomicBool::new(true);
        assert_eq!(
            run(vec![status(StatusCode::NOT_FOUND)], &stop),
            (PullOutcome::Stopped, 1, 0),
        );
    }

    #[test]
    fn stop_ends_transient_retries() {
        let stop = AtomicBool::new(false);
        let log = Logger::root(Discard, o!());
        let mut pulls = 0;
        let mut expiries = 0;
        let outcome = retry_initial_pull(
            || {
                pulls += 1;
                if pulls == 3 {
                    stop.store(true, Ordering::Relaxed);
                }
                status(StatusCode::SERVICE_UNAVAILABLE)
            },
            || expiries += 1,
            &stop,
            Duration::ZERO,
            &log,
            "test0",
        );
        assert_eq!((outcome, pulls, expiries), (PullOutcome::Stopped, 3, 0));
    }

    #[test]
    fn decode_backoff_schedule() {
        let interval = Duration::from_secs(1);
        let mut backoff = interval;
        let mut schedule = vec![backoff];
        for _ in 0..7 {
            backoff = next_decode_backoff(backoff, interval);
            schedule.push(backoff);
        }
        let expected: Vec<_> = [1, 2, 4, 8, 16, 32, 60, 60]
            .into_iter()
            .map(Duration::from_secs)
            .collect();
        assert_eq!(schedule, expected);

        let long = MAX_DECODE_BACKOFF + Duration::from_secs(30);
        assert_eq!(next_decode_backoff(long, long), long);

        assert_eq!(
            next_decode_backoff(Duration::ZERO, Duration::ZERO),
            Duration::ZERO,
        );
    }

    #[test]
    fn unpark_ends_parked_wait() {
        let stop = Arc::new(AtomicBool::new(false));
        let (pulled_tx, pulled_rx) = channel();
        let (done_tx, done_rx) = channel();

        let thread_stop = stop.clone();
        let handle = std::thread::spawn(move || {
            let log = Logger::root(Discard, o!());
            let outcome = retry_initial_pull(
                || {
                    let _ = pulled_tx.send(());
                    io_error()
                },
                || {},
                &thread_stop,
                Duration::from_secs(60),
                &log,
                "test0",
            );
            done_tx.send(outcome).unwrap();
        });

        pulled_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        stop.store(true, Ordering::Relaxed);
        handle.thread().unpark();

        let outcome = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("parked wait did not end on unpark");
        assert_eq!(outcome, PullOutcome::Stopped);
        handle.join().unwrap();
    }

    /// A pull worker that returns queued results.
    ///
    /// Each attempt signals `pulled` and waits on `release` before returning.
    struct TestWorker {
        worker: PullWorker,
        expiries: Arc<AtomicUsize>,
        pulled: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::Sender<()>,
    }

    fn spawn_worker(results: Vec<Result<(), ExchangeError>>) -> TestWorker {
        let stop = Arc::new(AtomicBool::new(false));
        let requested = Arc::new(AtomicBool::new(false));
        let (pulled_tx, pulled) = channel();
        let (release, release_rx) = channel::<()>();
        let expiries = Arc::new(AtomicUsize::new(0));

        let thread = {
            let stop = stop.clone();
            let requested = requested.clone();
            let expiries = expiries.clone();

            std::thread::spawn(move || {
                let log = Logger::root(Discard, o!());
                let mut results: VecDeque<_> = results.into();
                run_pull_worker(
                    || {
                        pulled_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        results.pop_front().expect("pull called too many times")
                    },
                    || {
                        expiries.fetch_add(1, Ordering::Relaxed);
                    },
                    &stop,
                    &requested,
                    Duration::ZERO,
                    &log,
                    "test0",
                );
            })
        };

        TestWorker {
            worker: PullWorker {
                stop,
                requested,
                thread,
            },
            expiries,
            pulled,
            release,
        }
    }

    impl TestWorker {
        fn wait_for_pull(&self) {
            self.pulled
                .recv_timeout(Duration::from_secs(5))
                .expect("worker did not start a pull");
        }

        fn finish_pull(&self) {
            self.release.send(()).unwrap();
        }

        fn request(&self) {
            self.worker.request();
        }

        fn no_pull_within(&self, d: Duration) {
            assert!(
                self.pulled.recv_timeout(d).is_err(),
                "worker pulled without a request",
            );
        }

        fn stop(self) -> usize {
            self.worker.stop().expect("worker panicked");
            self.expiries.load(Ordering::Relaxed)
        }

        fn join(self) -> usize {
            self.worker.thread.join().expect("worker panicked");
            self.expiries.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn worker_parks_after_initial_pull_until_requested() {
        let w = spawn_worker(vec![Ok(()), Ok(())]);

        w.wait_for_pull();
        w.finish_pull();

        w.no_pull_within(Duration::from_millis(200));

        w.request();
        w.wait_for_pull();
        w.finish_pull();

        assert_eq!(w.stop(), 0);
    }

    #[test]
    fn requests_during_a_pull_collapse_into_one() {
        let w = spawn_worker(vec![Ok(()), Ok(())]);

        w.wait_for_pull();
        w.request();
        w.request();
        w.request();
        w.finish_pull();

        w.wait_for_pull();
        w.finish_pull();
        w.no_pull_within(Duration::from_millis(200));

        assert_eq!(w.stop(), 0);
    }

    #[test]
    fn stop_ends_a_parked_worker() {
        let w = spawn_worker(vec![Ok(())]);

        w.wait_for_pull();
        w.finish_pull();
        assert_eq!(w.stop(), 0);
    }

    #[test]
    fn transient_error_on_request_keeps_the_worker_alive() {
        let w = spawn_worker(vec![Ok(()), io_error(), Ok(())]);

        w.wait_for_pull();
        w.finish_pull();

        w.request();
        w.wait_for_pull();
        w.finish_pull();

        w.request();
        w.wait_for_pull();
        w.finish_pull();

        assert_eq!(w.stop(), 0);
    }

    #[test]
    fn persistent_status_on_request_expires_and_exits() {
        let w = spawn_worker(vec![Ok(()), status(StatusCode::NOT_FOUND)]);

        w.wait_for_pull();
        w.finish_pull();

        w.request();
        w.wait_for_pull();
        w.finish_pull();

        assert_eq!(w.join(), 1);
    }

    #[test]
    fn failed_initial_pull_skips_the_request_loop() {
        let w = spawn_worker(vec![status(StatusCode::NOT_FOUND)]);

        w.wait_for_pull();
        w.finish_pull();

        assert_eq!(w.join(), 1);
    }

    #[test]
    fn worker_panic_requests_expiry_for_its_session() {
        let (tx, rx) = channel();
        let session = Arc::new(AtomicBool::new(false));

        let handle = {
            let tx = tx.clone();
            let session = session.clone();
            std::thread::spawn(move || {
                let log = Logger::root(Discard, o!());
                let _expire_on_panic = ExpireOnPanic {
                    tx: &tx,
                    session: &session,
                    peer: PEER_A,
                    log: &log,
                    if_name: "test0",
                };
                panic!("pull worker died");
            })
        };

        assert!(handle.join().is_err());
        match rx.try_recv().unwrap() {
            Event::Peer(PeerEvent::PullFailed { session: s, peer }) => {
                assert!(Arc::ptr_eq(&s, &session));
                assert_eq!(peer, PEER_A);
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    const PEER_A: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa);
    const PEER_B: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xb);

    fn failed_pull_event(
        session: &Arc<AtomicBool>,
        peer: Ipv6Addr,
    ) -> (Arc<AtomicBool>, Ipv6Addr) {
        let (tx, rx) = channel();
        let log = Logger::root(Discard, o!());
        let mut results = VecDeque::from([status(StatusCode::NOT_FOUND)]);
        let outcome = retry_initial_pull(
            || results.pop_front().expect("pull called too many times"),
            || {
                tx.send(Event::Peer(PeerEvent::PullFailed {
                    session: session.clone(),
                    peer,
                }))
                .unwrap()
            },
            session,
            Duration::ZERO,
            &log,
            "test0",
        );

        assert_eq!(outcome, PullOutcome::Expired);
        match rx.try_recv().unwrap() {
            Event::Peer(PeerEvent::PullFailed { session, peer }) => {
                (session, peer)
            }
            other => panic!("unexpected event {other:?}"),
        }
    }

    #[test]
    fn failed_pull_matches_its_own_session() {
        let session = Arc::new(AtomicBool::new(false));
        let (event, peer) = failed_pull_event(&session, PEER_A);
        assert!(is_current_session(&event, peer, &session, PEER_A));
    }

    #[test]
    fn delayed_failure_from_prior_session_is_ignored() {
        let prior = Arc::new(AtomicBool::new(false));
        let (event, peer) = failed_pull_event(&prior, PEER_A);
        let current = Arc::new(AtomicBool::new(false));
        assert!(!is_current_session(&event, peer, &current, PEER_A));
    }

    #[test]
    fn failure_after_peer_address_change_is_ignored() {
        let session = Arc::new(AtomicBool::new(false));
        let (event, peer) = failed_pull_event(&session, PEER_A);
        assert!(!is_current_session(&event, peer, &session, PEER_B));
    }
}
