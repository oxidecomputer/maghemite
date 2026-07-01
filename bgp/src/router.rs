// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    COMPONENT_BGP,
    config::RouterConfig,
    connection::BgpConnection,
    error::Error,
    fanout::{Egress, Fanout4, Fanout6},
    messages::{
        As4PathSegment, AsPathType, Community, PathAttribute,
        PathAttributeValue, PathOrigin,
    },
    policy::{load_checker, load_shaper},
    session::{
        AdminEvent, FsmEvent, NeighborInfo, PeerId, SessionInfo, SessionRunner,
    },
    unnumbered::UnnumberedManager,
};
use iddqd::{IdOrdItem, IdOrdMap, id_upcast};
use mg_common::{lock, read_lock, write_lock};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use rdb::{Asn, Db};
use rhai::AST;
use slog::Logger;
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
    },
};

/// Internal newtype for `IdOrdItem` impl — not exposed outside this module.
struct SessionHandle<Cnx: BgpConnection + 'static>(Arc<SessionRunner<Cnx>>);

impl<Cnx: BgpConnection + 'static> IdOrdItem for SessionHandle<Cnx> {
    type Key<'a> = &'a PeerId;

    fn key(&self) -> Self::Key<'_> {
        &self.0.neighbor.peer
    }

    id_upcast!();
}

/// Ordered map of active BGP sessions, keyed by PeerId derived from each
/// session's neighbor info. Wraps an `IdOrdMap` so the key can never
/// diverge from the value it indexes.
pub struct SessionMap<Cnx: BgpConnection + 'static>(
    IdOrdMap<SessionHandle<Cnx>>,
);

impl<Cnx: BgpConnection + 'static> Default for SessionMap<Cnx> {
    fn default() -> Self {
        Self(IdOrdMap::default())
    }
}

impl<Cnx: BgpConnection + 'static> SessionMap<Cnx> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, peer: &PeerId) -> Option<&Arc<SessionRunner<Cnx>>> {
        self.0.get(peer).map(|h| &h.0)
    }

    /// Inserts `session`, overwriting any existing entry for the same
    /// `PeerId`. Returns the displaced session if one was present.
    pub fn insert_overwrite(
        &mut self,
        session: Arc<SessionRunner<Cnx>>,
    ) -> Option<Arc<SessionRunner<Cnx>>> {
        self.0.insert_overwrite(SessionHandle(session)).map(|h| h.0)
    }

    pub fn remove(&mut self, peer: &PeerId) -> Option<Arc<SessionRunner<Cnx>>> {
        self.0.remove(peer).map(|h| h.0)
    }

    pub fn contains_key(&self, peer: &PeerId) -> bool {
        self.0.contains_key(peer)
    }

    pub fn values(&self) -> impl Iterator<Item = &Arc<SessionRunner<Cnx>>> {
        self.0.iter().map(|h| &h.0)
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&PeerId, &Arc<SessionRunner<Cnx>>)> {
        self.0.iter().map(|h| (&h.0.neighbor.peer, &h.0))
    }

    pub fn keys(&self) -> impl Iterator<Item = &PeerId> {
        self.0.iter().map(|h| &h.0.neighbor.peer)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

const UNIT_SESSION_RUNNER: &str = "session_runner";

pub struct Router<Cnx: BgpConnection + 'static> {
    /// The underlying routing information base (RIB) databse this router
    /// will update in response to BGP update messages (imported routes)
    /// and administrative API requests (originated routes).
    pub db: Db,

    /// The static configuration associated with this router.
    pub config: RouterConfig,

    /// A set of BGP session runners indexed by PeerId (IP or interface).
    /// Shared with the Dispatcher for connection routing.
    pub sessions: Arc<Mutex<SessionMap<Cnx>>>,

    /// Compiled policy programs.
    pub policy: Policy,

    /// The logger used by this router.
    pub log: Logger,

    /// A flag indicating whether this router should shut itself down.
    shutdown: AtomicBool,

    /// A flag indicating whether this router should initiate a
    /// graceful shutdown (RFC 8326) with its peers.
    graceful_shutdown: AtomicBool,

    /// A fanout is used to distribute originated prefixes to all peer
    /// sessions. In the event that redistribution becomes supported this
    /// will also act as a redistribution mechanism from one peer session
    /// to all others. If/when we do that, there will need to be export
    /// policy that governs what updates fan out to what peers.
    /// Note: Since peers can have any combination of address families enabled,
    ///       fanout must be maintained per address family. A peer session is
    ///       inserted into an address-family's fanout when it moves into
    ///       Established after negotiating that AFI/SAFI with the peer.
    pub fanout4: Arc<RwLock<Fanout4<Cnx>>>,
    pub fanout6: Arc<RwLock<Fanout6<Cnx>>>,
}

unsafe impl<Cnx: BgpConnection> Send for Router<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for Router<Cnx> {}

impl<Cnx: BgpConnection + 'static> Router<Cnx> {
    pub fn new(
        config: RouterConfig,
        log: Logger,
        db: Db,
        sessions: Arc<Mutex<SessionMap<Cnx>>>,
    ) -> Router<Cnx> {
        Self {
            config,
            sessions,
            log,
            shutdown: AtomicBool::new(false),
            graceful_shutdown: AtomicBool::new(false),
            db,
            fanout4: Arc::new(RwLock::new(Fanout4::<Cnx>::default())),
            fanout6: Arc::new(RwLock::new(Fanout6::<Cnx>::default())),
            policy: Policy::default(),
        }
    }

    // Get the session runner mapped to the peer id
    pub fn get_session(
        &self,
        peer: impl Into<PeerId>,
    ) -> Option<Arc<SessionRunner<Cnx>>> {
        let key: PeerId = peer.into();
        lock!(self.sessions).get(&key).cloned()
    }

    /// Spawn an FSM thread for the given session.
    /// This is used both when initially creating sessions and when restarting
    /// the router.
    fn spawn_session_thread(&self, session: Arc<SessionRunner<Cnx>>) {
        let peer_id = &session.neighbor.peer;
        slog::info!(
            self.log,
            "spawning session for {}",
            lock!(session.neighbor.name);
            slog::o!(
                "component" => crate::COMPONENT_BGP,
                "module" => crate::MOD_ROUTER,
                "unit" => UNIT_SESSION_RUNNER,
            )
        );
        std::thread::Builder::new()
            .name(format!("bgp-fsm-{}", peer_id))
            .spawn(move || {
                session.fsm_start();
            })
            .expect("failed to spawn BGP FSM thread");
    }

    /// Stop all session threads but retain session metadata.
    /// This allows the router to be restarted via run().
    /// Also cleans up fanout entries for all stopped sessions.
    fn stop_all_sessions(&self) {
        let sessions = lock!(self.sessions);
        for (peer, s) in sessions.iter() {
            if s.local_asn() != self.config.asn {
                continue;
            }
            self.remove_fanout(peer.clone());
            s.shutdown();
        }
    }

    /// Delete all sessions, clearing the SessionRunner and SessionEndpoint maps.
    /// This signals SessionRunner threads to exit and releases Arc<SessionRunner>
    /// references, allowing BgpConnections to drop and their threads to clean up.
    fn delete_all_sessions(&self) {
        let mut sessions = lock!(self.sessions);
        let peers: Vec<_> = sessions
            .iter()
            .filter(|(_, session)| session.local_asn() == self.config.asn)
            .map(|(peer, _)| peer.clone())
            .collect();

        for peer in peers {
            if let Some(session) = sessions.remove(&peer) {
                self.remove_fanout(peer);
                session.shutdown();
            }
        }
    }

    pub fn shutdown(&self) {
        slog::info!(
            self.log,
            "router (asn: {}, id: {}) received shutdown request, stopping sessions",
            self.config.asn, self.config.id;
            slog::o!(
                "component" => crate::COMPONENT_BGP,
                "module" => crate::MOD_ROUTER,
                "unit" => UNIT_SESSION_RUNNER,
            )
        );
        self.stop_all_sessions();
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn run(&self) {
        // Clear shutdown flag to allow router to restart
        self.shutdown.store(false, Ordering::Release);

        // Hold lock during entire iteration to prevent concurrent modifications
        let sessions = lock!(self.sessions);
        for session in sessions.values() {
            self.spawn_session_thread(session.clone());
        }
    }

    pub fn add_fanout4(
        &self,
        peer: impl Into<PeerId>,
        event_tx: Sender<FsmEvent<Cnx>>,
    ) {
        let mut fanout = write_lock!(self.fanout4);
        fanout.add_egress(
            peer.into(),
            Egress {
                event_tx: Some(event_tx),
                log: self.log.clone(),
            },
        )
    }

    pub fn add_fanout6(
        &self,
        peer: impl Into<PeerId>,
        event_tx: Sender<FsmEvent<Cnx>>,
    ) {
        let mut fanout = write_lock!(self.fanout6);
        fanout.add_egress(
            peer.into(),
            Egress {
                event_tx: Some(event_tx),
                log: self.log.clone(),
            },
        )
    }

    /// Remove a peer from any fanouts they're a member of.
    pub fn remove_fanout(&self, peer: impl Into<PeerId>) {
        let peer_id = peer.into();
        // Note: We intentionally use separate locks for fanout4 and fanout6 to allow
        // independent operation of IPv4 and IPv6 route distribution. There is a brief
        // window between releasing the fanout4 lock and acquiring the fanout6 lock
        // where the peer state is inconsistent (removed from one but not the other).
        //
        // This race is benign because:
        // 1. Fanout removal only occurs during administrative operations (session
        //    deletion, router shutdown), not the hot path
        // 2. Any route announcement sent during this window to the removed peer will
        //    fail harmlessly (channel disconnected)
        // 3. The final state is always consistent (peer removed from both fanouts)
        // 4. FsmState::Established transitions properly handle route announcements
        {
            let mut fanout = write_lock!(self.fanout4);
            fanout.remove_egress(&peer_id);
        }
        {
            let mut fanout = write_lock!(self.fanout6);
            fanout.remove_egress(&peer_id);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ensure_session(
        self: &Arc<Self>,
        neighbor: NeighborInfo,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Result<EnsureSessionResult<Cnx>, Error> {
        let sessions = lock!(self.sessions);
        if sessions.contains_key(&neighbor.peer) {
            drop(sessions);
            Ok(EnsureSessionResult::Updated(
                self.update_session(neighbor, info)?,
            ))
        } else {
            Ok(EnsureSessionResult::New(self.new_session_locked(
                sessions,
                neighbor,
                event_tx,
                event_rx,
                info,
                unnumbered_manager,
            )?))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_session(
        self: &Arc<Self>,
        neighbor: NeighborInfo,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let sessions = lock!(self.sessions);
        if sessions.contains_key(&neighbor.peer) {
            Err(Error::PeerExists)
        } else {
            self.new_session_locked(
                sessions,
                neighbor,
                event_tx,
                event_rx,
                info,
                unnumbered_manager,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_session_locked(
        self: &Arc<Self>,
        mut sessions: MutexGuard<SessionMap<Cnx>>,
        neighbor: NeighborInfo,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let session = Arc::new(Mutex::new(info));

        let runner = Arc::new(SessionRunner::new(
            session,
            event_rx,
            event_tx.clone(),
            neighbor,
            self.clone(),
            unnumbered_manager,
        ));

        sessions.insert_overwrite(runner.clone());
        drop(sessions);

        self.spawn_session_thread(runner.clone());

        Ok(runner)
    }

    pub fn update_session(
        self: &Arc<Self>,
        neighbor: NeighborInfo,
        info: SessionInfo,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let key = neighbor.peer.clone();
        let session = match lock!(self.sessions).get(&key) {
            None => return Err(Error::UnknownPeer(key)),
            Some(s) => s.clone(),
        };

        session.update_session_parameters(neighbor, info)?;

        Ok(session)
    }

    pub fn delete_session(&self, peer: impl Into<PeerId>) {
        let peer_id = peer.into();
        self.remove_fanout(peer_id.clone());
        if let Some(s) = lock!(self.sessions).remove(&peer_id) {
            s.shutdown();
        }
    }

    pub fn send_admin_event(&self, e: AdminEvent) -> Result<(), Error> {
        // Skip sending admin events if router is shutdown (sessions are stopped)
        if self.shutdown.load(Ordering::Acquire) {
            return Ok(());
        }

        for s in lock!(self.sessions).values() {
            s.send_event(FsmEvent::Admin(e.clone()))?;
        }
        Ok(())
    }

    pub fn create_origin4(&self, prefixes: Vec<IpNet>) -> Result<(), Error> {
        let prefix4: Vec<Ipv4Net> = prefixes
            .iter()
            .cloned()
            .filter_map(|x| match x {
                IpNet::V4(p4) => Some(p4),
                IpNet::V6(_) => None,
            })
            .collect();
        self.db.create_origin4(self.config.asn, &prefix4)?;

        // Skip network propagation if router is shutdown
        if !self.shutdown.load(Ordering::Acquire) {
            self.announce_origin4(prefix4);
        }
        Ok(())
    }

    pub fn set_origin4(&self, prefixes: Vec<IpNet>) -> Result<(), Error> {
        let origin4 = self.db.get_origin4(self.config.asn)?;
        let current: BTreeSet<&Ipv4Net> = origin4.iter().collect();

        let prefix4: Vec<Ipv4Net> = prefixes
            .iter()
            .cloned()
            .filter_map(|x| match x {
                IpNet::V4(p4) => Some(p4),
                IpNet::V6(_) => None,
            })
            .collect();

        let new: BTreeSet<&Ipv4Net> = prefix4.iter().collect();

        let to_withdraw: Vec<Ipv4Net> =
            current.difference(&new).map(|x| **x).collect();

        let to_announce: Vec<Ipv4Net> =
            new.difference(&current).map(|x| **x).collect();

        self.db.set_origin4(self.config.asn, &prefix4)?;

        // Skip network propagation if router is shutdown
        if !self.shutdown.load(Ordering::Acquire) {
            self.withdraw_origin4(to_withdraw);
            self.announce_origin4(to_announce);
        }
        Ok(())
    }

    pub fn clear_origin4(&self) -> Result<(), Error> {
        let current = self.db.get_origin4(self.config.asn)?;

        // Skip network propagation if router is shutdown
        if !self.shutdown.load(Ordering::Acquire) {
            self.withdraw_origin4(current);
        }
        self.db.clear_origin4(self.config.asn)?;
        Ok(())
    }

    /// Prefixes this router is currently originating into IPv4 unicast.
    pub fn originated4(&self) -> Result<Vec<Ipv4Net>, rdb::error::Error> {
        self.db.get_origin4(self.config.asn)
    }

    fn announce_origin4(&self, prefixes: Vec<Ipv4Net>) {
        if prefixes.is_empty() {
            return;
        }

        let pfx_str = prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        slog::debug!(
            self.log,
            "announcing originated IPv4 prefixes";
            "component" => COMPONENT_BGP,
            "prefixes" => format!("[{pfx_str}]"),
            "count" => prefixes.len(),
        );

        read_lock!(self.fanout4).send_all(prefixes, vec![]);
    }

    fn withdraw_origin4(&self, prefixes: Vec<Ipv4Net>) {
        if prefixes.is_empty() {
            return;
        }

        let pfx_str = prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        slog::debug!(
            self.log,
            "withdrawing originated IPv4 prefixes";
            "component" => COMPONENT_BGP,
            "prefixes" => format!("[{pfx_str}]"),
            "count" => prefixes.len(),
        );

        read_lock!(self.fanout4).send_all(vec![], prefixes);
    }

    pub fn create_origin6(&self, prefixes: Vec<IpNet>) -> Result<(), Error> {
        let prefix6: Vec<Ipv6Net> = prefixes
            .iter()
            .cloned()
            .filter_map(|x| match x {
                IpNet::V6(p6) => Some(p6),
                IpNet::V4(_) => None,
            })
            .collect();
        self.db.create_origin6(self.config.asn, &prefix6)?;

        // Skip network propagation if router is shutdown
        if !self.shutdown.load(Ordering::Acquire) {
            self.announce_origin6(prefix6);
        }
        Ok(())
    }

    pub fn set_origin6(&self, prefixes: Vec<IpNet>) -> Result<(), Error> {
        let origin6 = self.db.get_origin6(self.config.asn)?;
        let current: BTreeSet<&Ipv6Net> = origin6.iter().collect();

        let prefix6: Vec<Ipv6Net> = prefixes
            .iter()
            .cloned()
            .filter_map(|x| match x {
                IpNet::V6(p6) => Some(p6),
                IpNet::V4(_) => None,
            })
            .collect();

        let new: BTreeSet<&Ipv6Net> = prefix6.iter().collect();

        let to_withdraw: Vec<Ipv6Net> =
            current.difference(&new).map(|x| **x).collect();

        let to_announce: Vec<Ipv6Net> =
            new.difference(&current).map(|x| **x).collect();

        self.db.set_origin6(self.config.asn, &prefix6)?;

        // Skip network propagation if router is shutdown
        if !self.shutdown.load(Ordering::Acquire) {
            self.withdraw_origin6(to_withdraw);
            self.announce_origin6(to_announce);
        }
        Ok(())
    }

    pub fn clear_origin6(&self) -> Result<(), Error> {
        let current = self.db.get_origin6(self.config.asn)?;

        // Skip network propagation if router is shutdown
        if !self.shutdown.load(Ordering::Acquire) {
            self.withdraw_origin6(current);
        }
        self.db.clear_origin6(self.config.asn)?;
        Ok(())
    }

    /// Prefixes this router is currently originating into IPv6 unicast.
    pub fn originated6(&self) -> Result<Vec<Ipv6Net>, rdb::error::Error> {
        self.db.get_origin6(self.config.asn)
    }

    fn announce_origin6(&self, prefixes: Vec<Ipv6Net>) {
        if prefixes.is_empty() {
            return;
        }

        let pfx_str = prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        slog::debug!(
            self.log,
            "announcing originated IPv6 prefixes";
            "component" => COMPONENT_BGP,
            "prefixes" => format!("[{pfx_str}]"),
            "count" => prefixes.len(),
        );

        read_lock!(self.fanout6).send_all(prefixes, vec![]);
    }

    fn withdraw_origin6(&self, prefixes: Vec<Ipv6Net>) {
        if prefixes.is_empty() {
            return;
        }

        let pfx_str = prefixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");

        slog::debug!(
            self.log,
            "withdrawing originated IPv6 prefixes";
            "component" => COMPONENT_BGP,
            "prefixes" => format!("[{pfx_str}]"),
            "count" => prefixes.len(),
        );

        read_lock!(self.fanout6).send_all(vec![], prefixes);
    }

    pub fn base_attributes(&self) -> Vec<PathAttribute> {
        let mut path_attributes =
            vec![PathAttributeValue::Origin(PathOrigin::Igp).into()];

        if self.graceful_shutdown.load(Ordering::Relaxed) {
            path_attributes.push(
                PathAttributeValue::Communities(vec![
                    Community::GracefulShutdown,
                ])
                .into(),
            );
        }

        match self.config.asn {
            Asn::TwoOctet(asn) => {
                path_attributes.extend_from_slice(&[
                    PathAttributeValue::AsPath(vec![As4PathSegment {
                        typ: AsPathType::AsSequence,
                        value: vec![asn as u32],
                    }])
                    .into(),
                ]);
            }
            Asn::FourOctet(asn) => {
                path_attributes.extend_from_slice(&[
                    /* TODO according to RFC 4893 we do not have this as an
                     * explicit attribute type when 4-byte ASNs have been
                     * negotiated - but are there some circumstances when we'll
                     * need transitional mode?
                    PathAttributeValue::AsPath(vec![
                        AsPathSegment{
                            typ: AsPathType::AsSequence,
                            value: vec![AS_TRANS],
                        }
                    ]).into(),
                    */
                    PathAttributeValue::As4Path(vec![As4PathSegment {
                        typ: AsPathType::AsSequence,
                        value: vec![asn],
                    }])
                    .into(),
                ]);
            }
        }

        path_attributes
    }

    pub fn graceful_shutdown(&self, enabled: bool) -> Result<(), Error> {
        if enabled != self.graceful_shutdown.load(Ordering::Relaxed) {
            self.graceful_shutdown.store(enabled, Ordering::Relaxed);

            // Skip network propagation if router is shutdown
            if !self.shutdown.load(Ordering::Acquire) {
                self.announce_all()?;
            }
        }
        Ok(())
    }

    pub fn in_graceful_shutdown(&self) -> bool {
        self.graceful_shutdown.load(Ordering::Relaxed)
    }

    fn announce_all(&self) -> Result<(), Error> {
        let originated4 = self.db.get_origin4(self.config.asn)?;

        if !originated4.is_empty() {
            slog::debug!(
                self.log,
                "announcing all originated IPv4 prefixes";
                "component" => COMPONENT_BGP,
                "count" => originated4.len(),
            );

            read_lock!(self.fanout4).send_all(originated4, vec![]);
        }

        // Also announce IPv6 originated routes
        let originated6 = self.db.get_origin6(self.config.asn)?;

        if !originated6.is_empty() {
            slog::debug!(
                self.log,
                "announcing all originated IPv6 prefixes";
                "component" => COMPONENT_BGP,
                "count" => originated6.len(),
            );

            read_lock!(self.fanout6).send_all(originated6, vec![]);
        }

        Ok(())
    }
}

impl<Cnx: BgpConnection + 'static> Drop for Router<Cnx> {
    fn drop(&mut self) {
        // Stop all sessions when router is dropped to prevent thread leaks.
        // We don't set the shutdown flag here because it's not relevant during drop
        // (the router is being destroyed, not temporarily shutdown).
        self.delete_all_sessions();
    }
}

pub enum EnsureSessionResult<Cnx: BgpConnection + 'static> {
    New(Arc<SessionRunner<Cnx>>),
    Updated(Arc<SessionRunner<Cnx>>),
}

#[derive(Default, Clone)]
pub struct Policy {
    pub shaper: Arc<RwLock<Option<AST>>>,
    pub checker: Arc<RwLock<Option<AST>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum LoadPolicyError {
    #[error("Policy program compilation error: {0}")]
    Compilation(String),

    #[error("Policy program already exists")]
    Conflict,
}

#[derive(Debug, thiserror::Error)]
pub enum UnloadPolicyError {
    #[error("Policy program not loaded")]
    NotFound,
}

impl Policy {
    // Load a shaper and return the previously loaded shaper (if any).
    pub fn load_shaper(
        &self,
        program_source: &str,
        overwrite: bool,
    ) -> Result<Option<AST>, LoadPolicyError> {
        let mut current = self.shaper.write().unwrap();
        if current.is_some() && !overwrite {
            return Err(LoadPolicyError::Conflict);
        }
        let ast = load_shaper(program_source)
            .map_err(|e| LoadPolicyError::Compilation(e.to_string()))?;
        Ok(current.replace(ast))
    }

    pub fn unload_shaper(&self) -> Result<AST, UnloadPolicyError> {
        let mut current = self.shaper.write().unwrap();
        if current.is_none() {
            return Err(UnloadPolicyError::NotFound);
        }
        Ok(current.take().unwrap())
    }

    pub fn shaper_source(&self) -> Option<String> {
        self.shaper
            .read()
            .unwrap()
            .clone()
            .and_then(|ast| ast.source().map(|s| s.to_owned()))
    }

    pub fn load_checker(
        &self,
        program_source: &str,
        overwrite: bool,
    ) -> Result<Option<AST>, LoadPolicyError> {
        let mut current = self.checker.write().unwrap();
        if current.is_some() && !overwrite {
            return Err(LoadPolicyError::Conflict);
        }
        let ast = load_checker(program_source)
            .map_err(|e| LoadPolicyError::Compilation(e.to_string()))?;
        Ok(current.replace(ast))
    }

    pub fn unload_checker(&self) -> Result<AST, UnloadPolicyError> {
        let mut current = self.checker.write().unwrap();
        if current.is_none() {
            return Err(UnloadPolicyError::NotFound);
        }
        Ok(current.take().unwrap())
    }

    pub fn checker_source(&self) -> Option<String> {
        self.checker
            .read()
            .unwrap()
            .clone()
            .and_then(|ast| ast.source().map(|s| s.to_owned()))
    }
}
