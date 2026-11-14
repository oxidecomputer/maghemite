// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Routing state machine implementation. The `Init` -> `Solicit` ->
//! `Exchange` lifecycle drives kernel route programming via [`crate::sys`]
//! and reads interface addressing through `libnet`. This module is
//! illumos-only.

use super::{
    AdminEvent, Event, ExchangeSession, FsmState, NeighborEvent, PeerEvent,
    PrefixSet, SmContext, SmError, StateMachine,
};
use crate::db::RemovedNexthopRoutes;
use crate::discovery::Version;
use crate::exchange::UpdateMode;
use crate::{dbg, discovery, err, exchange, inf, wrn};
use ddm_api_types::db::RouterKind;
use ddm_protocol::v3::{PathVector, TunnelUpdate, UnderlayUpdate};
use ddm_protocol::v4::{
    MulticastOrigin, MulticastPathHop, MulticastPathVector, MulticastUpdate,
    Update,
};
use libnet::get_ipaddr_info;
use mg_common::lock;
use slog::Logger;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::thread::{JoinHandle, park_timeout, sleep, spawn};
use std::time::{Duration, Instant};

/// Periodic pull interval (V4 and later) for repairing missed multicast
/// updates.
const EXCHANGE_RESYNC_INTERVAL: Duration = Duration::from_secs(10);

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
    signals: Arc<PullSignals>,
    thread: JoinHandle<()>,
}

/// Flags shared between the state machine and its pull worker.
struct PullSignals {
    stop: Arc<AtomicBool>,
    pending: AtomicU8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum PendingPull {
    None = 0,
    ImportOnly = 1,
    Redistribute = 2,
}

impl From<UpdateMode> for PendingPull {
    fn from(mode: UpdateMode) -> Self {
        match mode {
            UpdateMode::ImportOnly => Self::ImportOnly,
            UpdateMode::Redistribute => Self::Redistribute,
        }
    }
}

impl From<u8> for PendingPull {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::ImportOnly,
            2 => Self::Redistribute,
            _ => unreachable!("invalid pending pull value {value}"),
        }
    }
}

impl From<PendingPull> for Option<UpdateMode> {
    fn from(pending: PendingPull) -> Self {
        match pending {
            PendingPull::None => None,
            PendingPull::ImportOnly => Some(UpdateMode::ImportOnly),
            PendingPull::Redistribute => Some(UpdateMode::Redistribute),
        }
    }
}

impl PullSignals {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: Arc::new(AtomicBool::new(false)),
            pending: AtomicU8::new(PendingPull::None as u8),
        })
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn request(&self, mode: UpdateMode) {
        self.pending
            .fetch_max(PendingPull::from(mode) as u8, Ordering::Relaxed);
    }

    /// Consume the pending request, returning the mode it asked for.
    fn take_request(&self) -> Option<UpdateMode> {
        PendingPull::from(
            self.pending
                .swap(PendingPull::None as u8, Ordering::Relaxed),
        )
        .into()
    }
}

impl PullWorker {
    /// Ask the worker to pull again. If a pull is already in progress the
    /// request waits for it to finish, while repeated requests collapse into
    /// one pull.
    ///
    /// A redistributing request is not downgraded by a later import-only
    /// request.
    fn request(&self, mode: UpdateMode) {
        self.signals.request(mode);
        self.thread.thread().unpark();
    }

    fn session(&self) -> &Arc<AtomicBool> {
        &self.signals.stop
    }

    /// Stop the worker and wait for it to exit.
    ///
    /// In-flight push handlers are drained separately with
    /// [`ExchangeSession::drain_updates`].
    fn stop(self) -> std::thread::Result<()> {
        self.signals.stop.store(true, Ordering::Relaxed);
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
/// The initial pull redistributes. Pending requests coalesce, with admin
/// sync's redistribution taking precedence over periodic import-only pulls.
///
/// `retry_initial_pull` handles the retry and backoff for the initial pull. A
/// requested pull runs once: a persistent HTTP status means the peer no
/// longer serves the negotiated exchange, and the worker requests expiry,
/// while transport and decode errors are left to the next request.
fn run_pull_worker(
    mut pull: impl FnMut(UpdateMode) -> Result<(), exchange::ExchangeError>,
    expire: impl Fn(),
    signals: &PullSignals,
    interval: Duration,
    log: &Logger,
    if_name: &str,
) {
    if retry_initial_pull(
        || pull(UpdateMode::Redistribute),
        &expire,
        &signals.stop,
        interval,
        log,
        if_name,
    ) != PullOutcome::Imported
    {
        return;
    }

    while let Some(mode) = wait_for_request(signals) {
        if pull_once(|| pull(mode), log, if_name) && !signals.stopped() {
            expire();
            return;
        }
    }
}

/// Park until a pull is requested or the worker is stopped.
///
/// Returns `None` when `stop` is set.
fn wait_for_request(signals: &PullSignals) -> Option<UpdateMode> {
    loop {
        if signals.stopped() {
            return None;
        }
        if let Some(mode) = signals.take_request() {
            return Some(mode);
        }
        std::thread::park();
    }
}

/// Run a requested pull, returning whether the peer must be expired.
///
/// Transport and decode errors wait for another request. A persistent HTTP
/// error requests peer expiry directly.
fn pull_once(
    pull: impl FnOnce() -> Result<(), exchange::ExchangeError>,
    log: &Logger,
    if_name: &str,
) -> bool {
    match pull() {
        Ok(()) => false,
        Err(ref e) if e.is_transient() => {
            wrn!(log, if_name, "exchange pull: {e}");
            false
        }
        Err(
            e @ (exchange::ExchangeError::SerdeJson(_)
            | exchange::ExchangeError::ResponseTooLarge { .. }),
        ) => {
            err!(log, if_name, "exchange pull: {e}");
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

/// Decode backoff cap (unless the solicit interval is longer).
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
            ref e @ (exchange::ExchangeError::SerdeJson(_)
            | exchange::ExchangeError::ResponseTooLarge { .. }) => {
                let wait = decode_backoff;
                err!(
                    log,
                    if_name,
                    "exchange pull: initial sync incomplete, retrying in \
                     {wait:?}: {e}"
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
                    Event::Peer(PeerEvent::Redistribute { update, .. }) => {
                        self.ctx.redistribute_withdrawals(update);
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
                self.ctx.router_id.to_string(),
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
                    let current_peer = lock!(self.ctx.iface.peer_identity)
                        .as_ref()
                        .map(|peer| peer.addr);
                    if current_peer != Some(addr) {
                        continue;
                    }
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
                Event::Peer(PeerEvent::Redistribute { update, .. }) => {
                    self.ctx.redistribute_withdrawals(update);
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
    session: Arc<ExchangeSession>,
    /// Sessions replaced by a version change, whose updates may still be
    /// installing routes concurrently. Expiry cancels and drains them
    /// along with the current session.
    retired: Vec<Arc<ExchangeSession>>,
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
            session: Arc::new(ExchangeSession::new(version)),
            retired: Vec::new(),
            log,
        }
    }

    fn sessions(&self) -> impl Iterator<Item = &Arc<ExchangeSession>> {
        std::iter::once(&self.session).chain(&self.retired)
    }

    fn pull_log(&self) -> Logger {
        self.log.new(slog::o!(
            "peer" => self.peer.to_string(),
            "version" => format!("{:?}", self.version),
        ))
    }

    fn start_pull_worker(&self) -> PullWorker {
        let signals = PullSignals::new();
        let peer = self.peer;
        let session = self.session.clone();
        let rt = self.ctx.rt.clone();
        let log = self.pull_log();
        let interval = self.ctx.config.solicit_interval;
        let ctx = self.ctx.clone();

        let thread = {
            let signals = signals.clone();
            std::thread::Builder::new()
                .name(format!("ddm-pull-{}", self.ctx.config.if_name))
                .spawn(move || {
                    let if_name = &ctx.config.if_name;
                    let stop = &signals.stop;
                    let _expire_on_panic = ExpireOnPanic {
                        tx: &ctx.tx,
                        session: stop,
                        peer,
                        log: &log,
                        if_name,
                    };
                    run_pull_worker(
                        |mode| {
                            crate::exchange::pull(
                                &ctx,
                                peer,
                                &session,
                                rt.clone(),
                                stop.clone(),
                                mode,
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
                        &signals,
                        interval,
                        &log,
                        if_name,
                    );
                })
                .expect("spawn ddm pull worker")
        };

        PullWorker { signals, thread }
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

    fn start_exchange_server(
        &self,
        session: Arc<ExchangeSession>,
    ) -> tokio::task::JoinHandle<()> {
        loop {
            match exchange::handler(
                self.ctx.clone(),
                self.ctx.config.addr,
                self.peer,
                session.clone(),
                self.log.clone(),
            ) {
                Ok(handle) => return handle,
                Err(e) => {
                    wrn!(
                        self.log,
                        self.ctx.config.if_name,
                        "exchange handler start: {e}",
                    );
                    inf!(self.log, self.ctx.config.if_name, "retrying in 1 s",);
                    sleep(Duration::from_secs(1));
                }
            }
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
            match exchange::probe_exchange_server(
                &self.ctx,
                &self.ctx.config.addr,
                self.version,
                &self.ctx.rt,
            ) {
                Ok(()) => break,
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
        self.sessions().for_each(|session| session.cancel());
        // Stop other threads that may update the rib after we clear for expiry.
        self.stop_pull_worker(pull_worker);

        exchange_thread.abort();
        // Drain in-flight updates. Updates that follow will see the cleared
        // session.
        let removed = {
            let mut session = self.ctx.iface.session();
            self.sessions().for_each(|session| session.drain_updates());
            self.retired.clear();
            *session = None;
            self.ctx.iface.clear_peer();
            self.ctx.db.remove_nexthop_routes(self.peer)
        };
        let routes = removed
            .underlay
            .iter()
            .map(|route| {
                let mut r = crate::sys::Route::new(
                    route.destination.addr().into(),
                    route.destination.width(),
                    route.nexthop.into(),
                );
                r.ifname.clone_from(&self.ctx.config.if_name);
                r
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
            &removed.tunnel,
        ) {
            err!(
                self.log,
                self.ctx.config.if_name,
                "failed to remove tunnel routes: {:#?} {e}",
                removed.tunnel
            );
        }
        self.redistribute_removed_routes(removed);
    }

    /// Redistribute removals after peer expiry or protocol downgrade.
    fn redistribute_removed_routes(&mut self, removed: RemovedNexthopRoutes) {
        if self.ctx.config.kind != RouterKind::Transit {
            return;
        }
        let RemovedNexthopRoutes {
            underlay: mut to_remove,
            tunnel: to_remove_tnl,
            multicast: to_remove_mcast,
        } = removed;

        dbg!(
            self.log,
            self.ctx.config.if_name,
            "redistributing withdraws to {} peers",
            self.ctx.event_channels.len()
        );

        // Only send withdraws for expirations that result in a total loss
        // of reachability to a destination for that given path.
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

        let underlay = (!to_remove.is_empty()).then(|| {
            UnderlayUpdate::withdraw(
                to_remove
                    .iter()
                    .map(|x| PathVector {
                        destination: x.destination,
                        path: {
                            let mut ps = x.path.clone();
                            ps.push(self.ctx.router_id.to_string());
                            ps
                        },
                    })
                    .collect(),
            )
        });

        let tunnel = (!to_remove_tnl.is_empty()).then(|| {
            TunnelUpdate::withdraw(
                to_remove_tnl.iter().cloned().map(Into::into).collect(),
            )
        });

        let multicast = (!to_remove_mcast.is_empty()).then(|| {
            MulticastUpdate::withdraw(
                to_remove_mcast
                    .iter()
                    .map(|route| MulticastPathVector {
                        origin: route.origin.clone(),
                        path: Vec::new(),
                    })
                    .collect(),
            )
        });

        if underlay.is_none() && tunnel.is_none() && multicast.is_none() {
            return;
        }

        let push = Arc::new(Update {
            underlay,
            tunnel,
            multicast,
        });

        super::send(
            Event::Peer(PeerEvent::Push(push)),
            &mut self.ctx.event_channels,
        );
    }

    fn local_hop(&self) -> MulticastPathHop {
        MulticastPathHop::new(self.ctx.router_id.clone(), self.ctx.config.addr)
    }

    fn reconcile_push(&self, push: MulticastUpdate) -> MulticastUpdate {
        if push.announce.is_empty() && push.withdraw.is_empty() {
            return push;
        }

        let origins = push
            .announce
            .iter()
            .chain(&push.withdraw)
            .map(|pv| &pv.origin);
        let peer_router_id = lock!(self.ctx.iface.peer_identity)
            .as_ref()
            .map(|peer| peer.router_id.clone());

        let paths = if self.ctx.config.kind == RouterKind::Transit
            && let Some(peer_router_id) = peer_router_id
        {
            self.ctx.db.snapshot_mcast_paths(origins, &peer_router_id)
        } else {
            self.ctx.db.snapshot_local_mcast_paths(origins)
        };

        crate::exchange::reconcile_multicast_update(
            push,
            &paths,
            &self.local_hop(),
        )
    }

    /// Send multicast routes, returning on whether the peer must expire
    /// or not.
    ///
    /// A send refused locally for exceeding the body limit does not expire
    /// the peer: a fresh session cannot shrink the update or chunk it and the
    /// periodic pull will attempt to repair it. Any other failure that affects
    /// this send (e.g., a timeout) expires the session, as it does for
    /// underlay and tunnel sends. HTTP errors from the peer, including a 413,
    /// are logged and counted within `put_update` without expiring.
    fn send_multicast(
        &self,
        groups: HashSet<MulticastPathVector>,
        send: MulticastSend,
        what: &str,
    ) -> bool {
        if groups.is_empty() {
            return false;
        }

        let Err(e) = send(
            &self.ctx,
            self.ctx.config.clone(),
            groups,
            self.peer,
            self.version,
            self.ctx.rt.clone(),
            self.log.clone(),
        ) else {
            return false;
        };
        err!(self.log, self.ctx.config.if_name, "{what}: {e}");
        if let exchange::ExchangeError::MulticastUpdateTooLarge { .. } = e {
            return false;
        }
        wrn!(
            self.log,
            self.ctx.config.if_name,
            "expiring peer {} due to failed {what}",
            self.peer,
        );
        true
    }

    fn announce_local_multicast(
        &self,
        origins: HashSet<MulticastOrigin>,
    ) -> bool {
        let hop = self.local_hop();
        let path_vectors = origins
            .into_iter()
            .map(|origin| MulticastPathVector {
                origin,
                path: vec![hop.clone()],
            })
            .collect();
        self.send_multicast(
            path_vectors,
            crate::exchange::announce_multicast,
            "announce multicast",
        )
    }

    fn withdraw_local_multicast(
        &self,
        origins: HashSet<MulticastOrigin>,
    ) -> bool {
        // Snapshot paths after dequeuing. A concurrent import
        // may have restored a withdrawn origin's path.
        let update = self.reconcile_push(MulticastUpdate::withdraw(
            origins
                .into_iter()
                .map(|origin| MulticastPathVector {
                    origin,
                    path: Vec::new(),
                })
                .collect(),
        ));

        self.send_multicast(
            update.announce,
            crate::exchange::announce_multicast,
            "replace withdrawn multicast path",
        ) || self.send_multicast(
            update.withdraw,
            crate::exchange::withdraw_multicast,
            "withdraw multicast",
        )
    }

    fn redistribute_peer_update(
        &mut self,
        update: Arc<Update>,
        session: &Arc<ExchangeSession>,
        peer: Ipv6Addr,
    ) {
        let current = peer == self.peer
            && !session.is_canceled()
            && Arc::ptr_eq(&self.session, session);
        if current {
            self.ctx.redistribute(Arc::unwrap_or_clone(update));
        } else {
            self.ctx.redistribute_withdrawals(update);
        }
    }

    fn restart_exchange(
        &mut self,
        version: Version,
        exchange_thread: &tokio::task::JoinHandle<()>,
        pull_worker: PullWorker,
    ) -> (tokio::task::JoinHandle<()>, PullWorker) {
        let prior_version = self.version;
        self.version = version;

        inf!(
            self.log,
            self.ctx.config.if_name,
            "peer {} {prior_version:?} -> {version:?}, restarting exchange",
            self.peer,
        );

        // Any pull still running under the prior version must
        // stop before a new one starts.
        self.stop_pull_worker(pull_worker);

        // A pre-V4 peer cannot withdraw its old multicast routes.
        let removed = {
            let mut session = self.ctx.iface.session();
            self.retired.push(self.session.clone());
            self.session = Arc::new(ExchangeSession::new(version));
            *session = Some(self.session.clone());
            if prior_version >= Version::V4 && version < Version::V4 {
                Some(self.ctx.db.remove_nexthop_mcast_routes(self.peer))
            } else {
                None
            }
        };

        exchange_thread.abort();
        if let Some(removed) = removed {
            self.redistribute_removed_routes(removed);
        }

        let exchange_thread = self.start_exchange_server(self.session.clone());
        self.wait_for_exchange_server_to_start();
        (exchange_thread, self.start_pull_worker())
    }
}

type MulticastSend = fn(
    &SmContext,
    super::Config,
    HashSet<MulticastPathVector>,
    Ipv6Addr,
    Version,
    Arc<tokio::runtime::Handle>,
    Logger,
) -> Result<(), exchange::ExchangeError>;

impl State for Exchange {
    fn run(&mut self, event: Receiver<Event>) -> Transition {
        self.ctx.iface.transition(FsmState::Exchange);
        *self.ctx.iface.session() = Some(self.session.clone());
        let mut exchange_thread =
            self.start_exchange_server(self.session.clone());

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

        let mut resync_deadline = Instant::now() + EXCHANGE_RESYNC_INTERVAL;
        loop {
            // Check the deadline before each receive op, ensuring that a
            // steady stream of events cannot postpone the resync.
            if Instant::now() >= resync_deadline {
                if self.version >= Version::V4 {
                    pull_worker.request(UpdateMode::ImportOnly);
                }
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
                            path: vec![self.ctx.router_id.to_string()],
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
                    if let Err(e) = crate::exchange::announce_tunnel(
                        &self.ctx,
                        self.ctx.config.clone(),
                        endpoints,
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
                            path: vec![self.ctx.router_id.to_string()],
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
                    if let Err(e) = crate::exchange::withdraw_tunnel(
                        &self.ctx,
                        self.ctx.config.clone(),
                        endpoints,
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
                Event::Admin(AdminEvent::AnnounceMulticast(groups)) => {
                    if self.announce_local_multicast(groups) {
                        return self.expire_and_transition(
                            Next::Solicit,
                            &exchange_thread,
                            pull_worker,
                            event,
                        );
                    }
                }
                Event::Admin(AdminEvent::WithdrawMulticast(origins)) => {
                    if self.withdraw_local_multicast(origins) {
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
                        pull_worker.session(),
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
                    pull_worker.request(UpdateMode::Redistribute);
                }
                Event::Admin(AdminEvent::NewExternalPeer(tx)) => {
                    if tx
                        .send(Event::Peer(PeerEvent::Push(Arc::new(Update {
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
                                .with_path_element(
                                    self.ctx.router_id.to_string(),
                                ),
                            ),
                            tunnel: None,
                            multicast: None,
                        }))))
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
                    let underlay =
                        update.underlay.as_ref().map_or((0, 0), |u| {
                            (u.announce.len(), u.withdraw.len())
                        });

                    let tunnel = update.tunnel.as_ref().map_or((0, 0), |t| {
                        (t.announce.len(), t.withdraw.len())
                    });

                    let multicast =
                        update.multicast.as_ref().map_or((0, 0), |m| {
                            (m.announce.len(), m.withdraw.len())
                        });

                    inf!(
                        self.log,
                        self.ctx.config.if_name,
                        "push to {}: (announce, withdraw) underlay \
                         {underlay:?} tunnel {tunnel:?} multicast \
                         {multicast:?}",
                        self.peer,
                    );

                    dbg!(
                        self.log,
                        self.ctx.config.if_name,
                        "push to {}: {update:#?}",
                        self.peer,
                    );

                    let update = Arc::unwrap_or_clone(update);
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

                    if let Some(push) = update.multicast {
                        let push = self.reconcile_push(push);
                        if self.send_multicast(
                            push.announce,
                            crate::exchange::announce_multicast,
                            "announce multicast",
                        ) || self.send_multicast(
                            push.withdraw,
                            crate::exchange::withdraw_multicast,
                            "withdraw multicast",
                        ) {
                            return self.expire_and_transition(
                                Next::Solicit,
                                &exchange_thread,
                                pull_worker,
                                event,
                            );
                        }
                    }
                }
                Event::Peer(PeerEvent::Redistribute {
                    update,
                    session,
                    peer,
                }) => {
                    self.redistribute_peer_update(update, &session, peer);
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
                    (exchange_thread, pull_worker) = self.restart_exchange(
                        version,
                        &exchange_thread,
                        pull_worker,
                    );
                }
            }
        }
    }
}

impl SmContext {
    fn redistribute_withdrawals(&mut self, update: Arc<Update>) {
        let update = Arc::unwrap_or_clone(update).withdrawals_only();
        if update.is_empty() {
            return;
        }
        self.redistribute(update);
    }

    fn redistribute(&mut self, mut update: Update) {
        dbg!(
            self.log,
            self.config.if_name,
            "redistributing update to {} peers",
            self.event_channels.len()
        );

        update.underlay = update.underlay.map(|u| {
            let router_id = self.router_id.to_string();
            let sans_loops = u.break_loops(&router_id);

            let announce_loop = u.announce.difference(&sans_loops.announce);
            let withdraw_loop = u.withdraw.difference(&sans_loops.withdraw);

            for prefix in announce_loop {
                wrn!(
                    self.log,
                    self.config.if_name,
                    "loop detected: dropping announcement: {prefix:?}"
                )
            }
            for prefix in withdraw_loop {
                wrn!(
                    self.log,
                    self.config.if_name,
                    "loop detected: dropping withdraw {prefix:?}",
                )
            }

            sans_loops.with_path_element(router_id)
        });
        super::send(
            Event::Peer(PeerEvent::Push(Arc::new(update))),
            &mut self.event_channels,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExpireOnPanic, MAX_DECODE_BACKOFF, PullOutcome, PullSignals,
        PullWorker, is_current_session, next_decode_backoff,
        retry_initial_pull, run_pull_worker,
    };
    use crate::exchange::{ExchangeError, UpdateMode};
    use crate::sm::{Event, PeerEvent};
    use hyper::StatusCode;
    use slog::{Discard, Logger, o};
    use std::collections::VecDeque;
    use std::net::Ipv6Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{RecvTimeoutError, channel};
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

    /// Bound stop and unpark after allowing the retry loop an idle interval.
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
        assert_eq!(
            pulled_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout),
        );
        assert_eq!(
            done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty),
        );
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
    /// Each attempt signals `pulled` with its mode and waits on `release`
    /// before returning.
    struct TestWorker {
        worker: PullWorker,
        expiries: Arc<AtomicUsize>,
        pulled: std::sync::mpsc::Receiver<UpdateMode>,
        release: std::sync::mpsc::Sender<()>,
    }

    fn spawn_worker(results: Vec<Result<(), ExchangeError>>) -> TestWorker {
        let signals = PullSignals::new();
        let (pulled_tx, pulled) = channel();
        let (release, release_rx) = channel::<()>();
        let expiries = Arc::new(AtomicUsize::new(0));

        let thread = {
            let signals = signals.clone();
            let expiries = expiries.clone();

            std::thread::spawn(move || {
                let log = Logger::root(Discard, o!());
                let mut results: VecDeque<_> = results.into();
                run_pull_worker(
                    |mode| {
                        pulled_tx.send(mode).unwrap();
                        release_rx.recv().unwrap();
                        results.pop_front().expect("pull called too many times")
                    },
                    || {
                        expiries.fetch_add(1, Ordering::Relaxed);
                    },
                    &signals,
                    Duration::ZERO,
                    &log,
                    "test0",
                );
            })
        };

        TestWorker {
            worker: PullWorker { signals, thread },
            expiries,
            pulled,
            release,
        }
    }

    impl TestWorker {
        fn wait_for_pull(&self) -> UpdateMode {
            self.pulled
                .recv_timeout(Duration::from_secs(5))
                .expect("worker did not start a pull")
        }

        fn finish_pull(&self) {
            self.release.send(()).unwrap();
        }

        fn request(&self) {
            self.worker.request(UpdateMode::ImportOnly);
        }

        fn request_redistribute(&self) {
            self.worker.request(UpdateMode::Redistribute);
        }

        fn no_pull_within(&self, d: Duration) {
            assert_eq!(
                self.pulled.recv_timeout(d),
                Err(RecvTimeoutError::Timeout),
                "worker pulled without a request or exited",
            );
        }

        fn stop(self) -> usize {
            self.worker.stop().expect("worker panicked");
            self.expiries.load(Ordering::Relaxed)
        }

        /// Use a helper thread to bound the blocking worker join.
        fn stop_within(self, d: Duration) -> usize {
            let (done_tx, done_rx) = channel();
            std::thread::spawn(move || {
                let _ = done_tx.send(self.stop());
            });
            done_rx
                .recv_timeout(d)
                .expect("stopped worker did not exit")
        }

        fn join(self) -> usize {
            self.worker.thread.join().expect("worker panicked");
            self.expiries.load(Ordering::Relaxed)
        }
    }

    /// Run the worker under the panic guard used by `start_pull_worker`.
    fn spawn_panicking_worker(
        peer: Ipv6Addr,
    ) -> (PullWorker, std::sync::mpsc::Receiver<Event>) {
        let signals = PullSignals::new();
        let (tx, events) = channel();

        let thread = {
            let signals = signals.clone();

            std::thread::spawn(move || {
                let log = Logger::root(Discard, o!());
                let _expire_on_panic = ExpireOnPanic {
                    tx: &tx,
                    session: &signals.stop,
                    peer,
                    log: &log,
                    if_name: "test0",
                };
                run_pull_worker(
                    |_| -> Result<(), ExchangeError> {
                        panic!("pull worker died")
                    },
                    || {},
                    &signals,
                    Duration::ZERO,
                    &log,
                    "test0",
                );
            })
        };

        (PullWorker { signals, thread }, events)
    }

    /// Collapsed requests preserve redistribution regardless of arrival order.
    #[test]
    fn pending_pull_requests_join_to_redistribute() {
        let signals = PullSignals::new();
        assert_eq!(signals.take_request(), None);

        signals.request(UpdateMode::ImportOnly);
        assert_eq!(signals.take_request(), Some(UpdateMode::ImportOnly));
        assert_eq!(signals.take_request(), None);

        signals.request(UpdateMode::ImportOnly);
        signals.request(UpdateMode::Redistribute);
        assert_eq!(signals.take_request(), Some(UpdateMode::Redistribute));
        assert_eq!(signals.take_request(), None);

        signals.request(UpdateMode::Redistribute);
        signals.request(UpdateMode::ImportOnly);
        assert_eq!(signals.take_request(), Some(UpdateMode::Redistribute));
        assert_eq!(signals.take_request(), None);
    }

    #[test]
    fn worker_parks_after_initial_pull_until_requested() {
        let w = spawn_worker(vec![Ok(()), Ok(())]);

        assert_eq!(w.wait_for_pull(), UpdateMode::Redistribute);
        w.finish_pull();

        w.no_pull_within(Duration::from_millis(200));

        w.request();
        assert_eq!(w.wait_for_pull(), UpdateMode::ImportOnly);
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

    /// An import-only request must preserve an already queued redistribution.
    #[test]
    fn redistribute_request_is_not_downgraded_by_import_only() {
        let w = spawn_worker(vec![Ok(()), Ok(()), Ok(())]);

        w.wait_for_pull();
        w.request_redistribute();
        w.request();
        w.finish_pull();

        assert_eq!(w.wait_for_pull(), UpdateMode::Redistribute);
        w.finish_pull();

        w.request();
        assert_eq!(w.wait_for_pull(), UpdateMode::ImportOnly);
        w.finish_pull();

        assert_eq!(w.stop(), 0);
    }

    /// Check bounded shutdown after the worker has had an idle interval.
    #[test]
    fn stop_ends_a_parked_worker() {
        let w = spawn_worker(vec![Ok(())]);

        w.wait_for_pull();
        w.finish_pull();
        w.no_pull_within(Duration::from_millis(50));
        assert_eq!(w.stop_within(Duration::from_secs(5)), 0);
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

    /// A panic in the pull closure requests expiry for that worker's session.
    #[test]
    fn worker_panic_requests_expiry_for_its_session() {
        let (worker, events) = spawn_panicking_worker(PEER_A);

        let event = events
            .recv_timeout(Duration::from_secs(5))
            .expect("panicking worker did not request expiry");
        match event {
            Event::Peer(PeerEvent::PullFailed { session, peer }) => {
                assert!(Arc::ptr_eq(&session, worker.session()));
                assert_eq!(peer, PEER_A);
            }
            other => panic!("unexpected event {other:?}"),
        }
        assert!(worker.thread.join().is_err());
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
