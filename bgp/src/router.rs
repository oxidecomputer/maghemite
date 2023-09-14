use crate::config::PeerConfig;
use crate::config::RouterConfig;
use crate::connection::BgpConnection;
use crate::error::Error;
use crate::fanout::{Egress, Fanout};
use crate::messages::{
    As4PathSegment, AsPathType, PathAttributeValue, PathOrigin, Prefix,
    UpdateMessage,
};
use crate::session::{Asn, FsmEvent, NeighborInfo, Session, SessionRunner};
use rdb::{Db, Route4Key};
use slog::Logger;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::spawn;
use std::time::Duration;

pub struct Router<Cnx: BgpConnection> {
    pub db: Db,
    pub config: RouterConfig,
    pub sessions: Mutex<BTreeMap<IpAddr, Arc<SessionRunner<Cnx>>>>,

    log: Logger,
    shutdown: AtomicBool,
    addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
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
            db,
            sessions: Mutex::new(BTreeMap::new()),
            fanout: Arc::new(RwLock::new(Fanout::default())),
        }
    }

    pub fn get_session(&self, addr: IpAddr) -> Option<Arc<SessionRunner<Cnx>>> {
        self.sessions.lock().unwrap().get(&addr).cloned()
    }

    pub fn shutdown(&self) {
        for (addr, s) in self.sessions.lock().unwrap().iter() {
            self.addr_to_session.lock().unwrap().remove(addr);
            s.shutdown();
        }
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn run(&self) {
        for s in self.sessions.lock().unwrap().values() {
            let session = s.clone();
            spawn(move || {
                session.start();
            });
        }
    }

    pub fn add_fanout(&self, peer: IpAddr, event_tx: Sender<FsmEvent<Cnx>>) {
        let mut fanout = self.fanout.write().unwrap();
        fanout.add_egress(
            peer,
            Egress {
                event_tx: Some(event_tx.clone()),
            },
        )
    }

    pub fn remove_fanout(&self, peer: IpAddr) {
        let mut fanout = self.fanout.write().unwrap();
        fanout.remove_egress(peer);
    }

    pub fn new_session(
        &self,
        peer: PeerConfig,
        bind_addr: SocketAddr,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
    ) -> Result<Arc<SessionRunner<Cnx>>, Error> {
        let session = Session::new();

        let mut a2s = self.addr_to_session.lock().unwrap();
        if a2s.contains_key(&peer.host.ip()) {
            return Err(Error::PeerExists);
        }

        a2s.insert(peer.host.ip(), event_tx.clone());

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
            session,
            event_rx,
            event_tx.clone(),
            neighbor.clone(),
            self.config.asn,
            self.config.id,
            Duration::from_millis(peer.resolution),
            Some(bind_addr),
            self.db.clone(),
            self.fanout.clone(),
            self.log.clone(),
        ));

        let r = runner.clone();
        spawn(move || {
            r.start();
        });

        self.add_fanout(neighbor.host.ip(), event_tx);
        self.sessions
            .lock()
            .unwrap()
            .insert(neighbor.host.ip(), runner.clone());

        Ok(runner)
    }

    pub fn delete_session(&self, addr: IpAddr) {
        self.addr_to_session.lock().unwrap().remove(&addr);
        self.remove_fanout(addr);
        if let Some(s) = self.sessions.lock().unwrap().remove(&addr) {
            s.shutdown();
        }
    }

    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        for s in self.sessions.lock().unwrap().values() {
            s.send_event(e.clone())?;
        }
        Ok(())
    }

    pub fn originate4(
        &self,
        nexthop: Ipv4Addr,
        prefixes: Vec<Prefix>,
    ) -> Result<(), Error> {
        let mut update = UpdateMessage {
            path_attributes: vec![
                //TODO hardcode
                PathAttributeValue::Origin(PathOrigin::Egp).into(),
                PathAttributeValue::NextHop(nexthop.into()).into(),
            ],
            ..Default::default()
        };
        match self.config.asn {
            Asn::TwoOctet(asn) => {
                update.path_attributes.extend_from_slice(&[
                    PathAttributeValue::AsPath(vec![As4PathSegment {
                        typ: AsPathType::AsSequence,
                        value: vec![asn as u32],
                    }])
                    .into(),
                ]);
            }
            Asn::FourOctet(asn) => {
                update.path_attributes.extend_from_slice(&[
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
        for p in &prefixes {
            update.nlri.push(p.clone());
            self.db
                .add_origin4(Route4Key {
                    prefix: p.into(),
                    nexthop,
                })
                .unwrap();
        }

        self.fanout.read().unwrap().send_all(&update);

        Ok(())
    }
}
