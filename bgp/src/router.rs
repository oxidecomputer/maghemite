// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::config::PeerConfig;
use crate::config::RouterConfig;
use crate::connection::BgpConnection;
use crate::error::Error;
use crate::fanout::{Egress, Fanout};
use crate::messages::{
    As4PathSegment, AsPathType, Community, PathAttribute, PathAttributeValue,
    PathOrigin, Prefix, UpdateMessage,
};
use crate::session::{FsmEvent, NeighborInfo, SessionInfo, SessionRunner};
use mg_common::{lock, read_lock, write_lock};
use rdb::{Asn, Db};
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
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

    pub fn new_session(
        self: &Arc<Self>,
        peer: PeerConfig,
        bind_addr: SocketAddr,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        info: SessionInfo,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let mut a2s = lock!(self.addr_to_session);
        if a2s.contains_key(&peer.host.ip()) {
            return Err(Error::PeerExists);
        }

        a2s.insert(peer.host.ip(), event_tx.clone());
        drop(a2s);

        let neighbor = NeighborInfo {
            name: peer.name.clone(),
            host: peer.host,
        };

        let runner = Arc::new(SessionRunner::new(
            Duration::from_secs(peer.connect_retry),
            Duration::from_secs(peer.keepalive),
            Duration::from_secs(peer.hold_time),
            Duration::from_secs(peer.idle_hold_time),
            Duration::from_secs(peer.delay_open),
            Arc::new(Mutex::new(info)),
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

    pub fn originate4(&self, prefixes: Vec<Prefix>) -> Result<(), Error> {
        let mut update = UpdateMessage {
            path_attributes: self.base_attributes(),
            ..Default::default()
        };

        for p in &prefixes {
            update.nlri.push(p.clone());
            self.db.add_origin4(p.into())?;
        }

        if !update.nlri.is_empty() {
            read_lock!(self.fanout).send_all(&update);
        }

        Ok(())
    }

    pub fn withdraw4(&self, prefixes: Vec<Prefix>) -> Result<(), Error> {
        let mut update = UpdateMessage {
            path_attributes: self.base_attributes(),
            ..Default::default()
        };

        for p in &prefixes {
            update.withdrawn.push(p.clone());
            self.db.remove_origin4(p.into())?;
        }

        if !update.withdrawn.is_empty() {
            read_lock!(self.fanout).send_all(&update);
        }

        Ok(())
    }

    pub fn base_attributes(&self) -> Vec<PathAttribute> {
        let mut path_attributes = vec![
            //TODO hardcode
            PathAttributeValue::Origin(PathOrigin::Egp).into(),
        ];

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
        self.graceful_shutdown.store(enabled, Ordering::Relaxed);
        self.announce_all()
    }

    pub fn in_graceful_shutdown(&self) -> bool {
        self.graceful_shutdown.load(Ordering::Relaxed)
    }

    fn announce_all(&self) -> Result<(), Error> {
        let originated = self.db.get_originated4()?;

        let mut update = UpdateMessage {
            path_attributes: self.base_attributes(),
            ..Default::default()
        };
        for p in &originated {
            update.nlri.push((*p).into());
            self.db.add_origin4(*p)?;
        }
        read_lock!(self.fanout).send_all(&update);

        Ok(())
    }
}
