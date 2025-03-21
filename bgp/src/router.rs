// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::PeerConfig;
use crate::config::RouterConfig;
use crate::connection::BgpConnection;
use crate::error::Error;
use crate::fanout::{Egress, Fanout};
use crate::messages::PathOrigin;
use crate::messages::{
    As4PathSegment, AsPathType, Community, PathAttribute, PathAttributeValue,
    Prefix, UpdateMessage,
};
use crate::policy::load_checker;
use crate::policy::load_shaper;
use crate::session::{FsmEvent, NeighborInfo, SessionInfo, SessionRunner};
use mg_common::{lock, read_lock, write_lock};
use rdb::Prefix4;
use rdb::{Asn, Db};
use rhai::AST;
use slog::Logger;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::spawn;
use std::time::Duration;

pub struct Router<Cnx: BgpConnection> {
    /// The underlying routing information base (RIB) databse this router
    /// will update in response to BGP update messages (imported routes)
    /// and administrative API requests (originated routes).
    pub db: Db,

    /// The static configuration associated with this router.
    pub config: RouterConfig,

    /// A set of BGP session runners indexed by peer IP address.
    pub sessions: Mutex<BTreeMap<IpAddr, Arc<SessionRunner<Cnx>>>>,

    /// Compiled policy programs.
    pub policy: Policy,

    /// The logger used by this router.
    log: Logger,

    /// A flag indicating whether this router should shut itself down.
    shutdown: AtomicBool,

    /// A flag indicating whether this router should initiate a
    /// graceful shutdown (RFC 8326) with its peers.
    graceful_shutdown: AtomicBool,

    /// A set of event channels indexed by peer IP address. These channels
    /// are used for cross-peer session communications.
    addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,

    /// A fanout is used to distribute originated prefixes to all peer
    /// sessions. In the event that redistribution becomes supported this
    /// will also act as a redistribution mechanism from one peer session
    /// to all others. If/when we do that, there will need to be export
    /// policy that governs what updates fan out to what peers.
    fanout: Arc<RwLock<Fanout<Cnx>>>,
}

unsafe impl<Cnx: BgpConnection> Send for Router<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for Router<Cnx> {}

impl<Cnx: BgpConnection + 'static> Router<Cnx> {
    pub fn new(
        config: RouterConfig,
        log: Logger,
        db: Db,
        addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
    ) -> Router<Cnx> {
        Self {
            config,
            addr_to_session,
            log,
            shutdown: AtomicBool::new(false),
            graceful_shutdown: AtomicBool::new(false),
            db,
            sessions: Mutex::new(BTreeMap::new()),
            fanout: Arc::new(RwLock::new(Fanout::default())),
            policy: Policy::default(),
        }
    }

    pub fn get_session(&self, addr: IpAddr) -> Option<Arc<SessionRunner<Cnx>>> {
        lock!(self.sessions).get(&addr).cloned()
    }

    pub fn shutdown(&self) {
        for (addr, s) in lock!(self.sessions).iter() {
            lock!(self.addr_to_session).remove(addr);
            s.shutdown();
        }
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn run(&self) {
        for s in lock!(self.sessions).values() {
            let session = s.clone();
            slog::info!(self.log, "spawning session");
            spawn(move || {
                session.start();
            });
        }
    }

    pub fn add_fanout(&self, peer: IpAddr, event_tx: Sender<FsmEvent<Cnx>>) {
        let mut fanout = write_lock!(self.fanout);
        fanout.add_egress(
            peer,
            Egress {
                event_tx: Some(event_tx.clone()),
                log: self.log.clone(),
            },
        )
    }

    pub fn remove_fanout(&self, peer: IpAddr) {
        let mut fanout = write_lock!(self.fanout);
        fanout.remove_egress(peer);
    }

    pub fn ensure_session(
        self: &Arc<Self>,
        peer: PeerConfig,
        bind_addr: SocketAddr,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
    ) -> Result<EnsureSessionResult<Cnx>, Error> {
        let a2s = lock!(self.addr_to_session);
        if a2s.contains_key(&peer.host.ip()) {
            Ok(EnsureSessionResult::Updated(
                self.update_session(peer, info)?,
            ))
        } else {
            Ok(EnsureSessionResult::New(self.new_session_locked(
                a2s, peer, bind_addr, event_tx, event_rx, info,
            )?))
        }
    }

    pub fn new_session(
        self: &Arc<Self>,
        peer: PeerConfig,
        bind_addr: SocketAddr,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let a2s = lock!(self.addr_to_session);
        if a2s.contains_key(&peer.host.ip()) {
            Err(Error::PeerExists)
        } else {
            self.new_session_locked(
                a2s, peer, bind_addr, event_tx, event_rx, info,
            )
        }
    }

    pub fn new_session_locked(
        self: &Arc<Self>,
        mut a2s: MutexGuard<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>,
        peer: PeerConfig,
        bind_addr: SocketAddr,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        a2s.insert(peer.host.ip(), event_tx.clone());
        drop(a2s);

        let neighbor = NeighborInfo {
            name: Arc::new(Mutex::new(peer.name.clone())),
            host: peer.host,
        };

        let runner = Arc::new(SessionRunner::new(
            Duration::from_secs(peer.connect_retry),
            Duration::from_secs(peer.keepalive),
            Duration::from_secs(peer.hold_time),
            Duration::from_secs(peer.idle_hold_time),
            Duration::from_secs(peer.delay_open),
            Arc::new(Mutex::new(info.clone())),
            event_rx,
            event_tx.clone(),
            neighbor.clone(),
            self.config.asn,
            self.config.id,
            Duration::from_millis(peer.resolution),
            Some(bind_addr),
            self.db.clone(),
            self.fanout.clone(),
            //TODO remove all the other self properties in favor just passing
            //     the router through.
            self.clone(),
            self.log.clone(),
        ));

        let r = runner.clone();
        slog::info!(self.log, "spawning new session");
        spawn(move || {
            r.start();
        });

        self.add_fanout(neighbor.host.ip(), event_tx);
        lock!(self.sessions).insert(neighbor.host.ip(), runner.clone());

        Ok(runner)
    }

    pub fn update_session(
        self: &Arc<Self>,
        peer: PeerConfig,
        info: SessionInfo,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let session = match lock!(self.sessions).get(&peer.host.ip()) {
            None => return Err(Error::UnknownPeer(peer.host.ip())),
            Some(s) => s.clone(),
        };

        session.update_session_parameters(peer, info)?;

        Ok(session)
    }

    pub fn delete_session(&self, addr: IpAddr) {
        lock!(self.addr_to_session).remove(&addr);
        self.remove_fanout(addr);
        if let Some(s) = lock!(self.sessions).remove(&addr) {
            s.shutdown();
        }
    }

    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        for s in lock!(self.sessions).values() {
            s.send_event(e.clone())?;
        }
        Ok(())
    }

    pub fn create_origin4(&self, prefixes: Vec<Prefix>) -> Result<(), Error> {
        let prefix4: Vec<Prefix4> =
            prefixes.iter().cloned().map(|x| x.as_prefix4()).collect();
        self.db.create_origin4(&prefix4)?;
        self.announce_origin4(&prefixes);
        Ok(())
    }

    pub fn set_origin4(&self, prefixes: Vec<Prefix>) -> Result<(), Error> {
        let origin4 = self.db.get_origin4()?;
        let current: BTreeSet<&Prefix4> = origin4.iter().collect();

        let prefix4: Vec<Prefix4> =
            prefixes.iter().cloned().map(|x| x.as_prefix4()).collect();

        let new: BTreeSet<&Prefix4> = prefix4.iter().collect();

        let to_withdraw: Vec<_> =
            current.difference(&new).map(|x| (**x).into()).collect();

        let to_announce: Vec<_> =
            new.difference(&current).map(|x| (**x).into()).collect();

        self.db.set_origin4(&prefix4)?;

        self.withdraw_origin4(&to_withdraw);
        self.announce_origin4(&to_announce);
        Ok(())
    }

    pub fn clear_origin4(&self) -> Result<(), Error> {
        let current = self.db.get_origin4()?;
        let prefix: Vec<Prefix> =
            current.iter().cloned().map(Into::into).collect();
        self.withdraw_origin4(&prefix);
        self.db.clear_origin4()?;
        Ok(())
    }

    fn announce_origin4(&self, prefixes: &Vec<Prefix>) {
        let mut update = UpdateMessage {
            path_attributes: self.base_attributes(),
            ..Default::default()
        };

        for p in prefixes {
            update.nlri.push(p.clone());
        }

        if !update.nlri.is_empty() {
            read_lock!(self.fanout).send_all(&update);
        }
    }

    pub fn withdraw_origin4(&self, prefixes: &Vec<Prefix>) {
        let mut update = UpdateMessage {
            path_attributes: self.base_attributes(),
            ..Default::default()
        };

        for p in prefixes {
            update.withdrawn.push(p.clone());
        }

        if !update.withdrawn.is_empty() {
            read_lock!(self.fanout).send_all(&update);
        }
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
            self.announce_all()?;
        }
        Ok(())
    }

    pub fn in_graceful_shutdown(&self) -> bool {
        self.graceful_shutdown.load(Ordering::Relaxed)
    }

    fn announce_all(&self) -> Result<(), Error> {
        let originated = self.db.get_origin4()?;

        let mut update = UpdateMessage {
            path_attributes: self.base_attributes(),
            ..Default::default()
        };
        for p in &originated {
            update.nlri.push((*p).into());
        }
        read_lock!(self.fanout).send_all(&update);

        Ok(())
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
