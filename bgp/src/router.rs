use crate::config::PeerConfig;
use crate::config::RouterConfig;
use crate::connection::{BgpConnection, BgpListener};
use crate::error::Error;
use crate::fanout::Rule4;
use crate::fanout::{Egress, Fanout};
use crate::messages::{PathAttributeValue, Prefix, UpdateMessage};
use crate::session::{FsmEvent, SessionRunner};
use crate::session::{NeighborInfo, Session};
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

    config: RouterConfig,
    listen: String,
    log: Logger,
    shutdown: AtomicBool,
    sessions: Mutex<Vec<Arc<SessionRunner<Cnx>>>>,
    addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
    fanout: Arc<RwLock<Fanout<Cnx>>>,
}

unsafe impl<Cnx: BgpConnection> Send for Router<Cnx> {}
unsafe impl<Cnx: BgpConnection> Sync for Router<Cnx> {}

impl<Cnx: BgpConnection + 'static> Router<Cnx> {
    pub fn new(
        listen: String,
        config: RouterConfig,
        log: Logger,
        db: Db,
    ) -> Router<Cnx> {
        Self {
            config,
            listen,
            addr_to_session: Arc::new(Mutex::new(BTreeMap::new())),
            log,
            shutdown: AtomicBool::new(false),
            db,
            sessions: Mutex::new(Vec::new()),
            fanout: Arc::new(RwLock::new(Fanout::default())),
        }
    }

    pub fn get_session(&self, index: usize) -> Option<Arc<SessionRunner<Cnx>>> {
        self.sessions.lock().unwrap().get(index).cloned()
    }

    pub fn shutdown(&self) {
        for s in self.sessions.lock().unwrap().iter() {
            s.shutdown();
        }
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn run<Listener: BgpListener<Cnx>>(&self) {
        for s in self.sessions.lock().unwrap().iter() {
            let session = s.clone();
            spawn(move || {
                session.start();
            });
        }
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                self.shutdown.store(false, Ordering::Release);
                break;
            }
            let listener = Listener::bind(&self.listen).unwrap();
            let conn = match listener.accept(
                self.log.clone(),
                self.addr_to_session.clone(),
                Duration::from_millis(100),
            ) {
                Ok(c) => c,
                Err(crate::error::Error::Timeout) => {
                    continue;
                }
                Err(_e) => {
                    //TODO log
                    continue;
                }
            };
            let addr = conn.peer().ip();
            match self.addr_to_session.lock().unwrap().get(&addr) {
                Some(tx) => {
                    tx.send(FsmEvent::Connected(conn)).unwrap();
                }
                None => continue,
            }
        }
    }

    pub fn update_fanout(&self, peer: IpAddr, event_tx: Sender<FsmEvent<Cnx>>) {
        let mut fanout = self.fanout.write().unwrap();
        fanout.add_egress(
            peer,
            Egress {
                rules: Vec::new(), //TODO
                event_tx: event_tx.clone(),
            },
        )
    }

    pub fn add_export_policy(&self, addr: IpAddr, rule: Rule4) {
        self.fanout.write().unwrap().add_rule(addr, rule).unwrap();
    }

    pub fn new_session(
        &self,
        peer: PeerConfig,
        bind_addr: SocketAddr,
        event_tx: Sender<FsmEvent<Cnx>>,
        event_rx: Receiver<FsmEvent<Cnx>>,
        db: Db,
    ) -> Arc<SessionRunner<Cnx>> {
        let session = Session::new();

        self.addr_to_session
            .lock()
            .unwrap()
            .insert(peer.host.ip(), event_tx.clone());

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
            db,
            self.fanout.clone(),
            self.log.clone(),
        ));

        let r = runner.clone();
        spawn(move || {
            r.start();
        });

        self.update_fanout(neighbor.host.ip(), event_tx);
        self.sessions.lock().unwrap().push(runner.clone());

        runner
    }

    pub fn send_event(&self, e: FsmEvent<Cnx>) -> Result<(), Error> {
        for s in self.sessions.lock().unwrap().iter() {
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
                PathAttributeValue::NextHop(nexthop.into()).into()
            ],
            ..Default::default()
        };
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
