use crate::config::PeerConfig;
use crate::config::RouterConfig;
use crate::connection::{BgpConnection, BgpListener};
use crate::session::{FsmEvent, SessionRunner};
use crate::session::{NeighborInfo, Session};
use rdb::Db;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::spawn;
use std::time::Duration;

pub struct Router<Cnx: BgpConnection> {
    pub config: RouterConfig,
    pub listen: String,
    pub addr_to_session: Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>,
    pub log: Logger,
    pub shutdown: AtomicBool,
    pub db: Db,
    pub sessions: Mutex<Vec<Arc<SessionRunner<Cnx>>>>,
}

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
            addr_to_session: Mutex::new(BTreeMap::new()),
            log,
            shutdown: AtomicBool::new(false),
            db,
            sessions: Mutex::new(Vec::new()),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn run<Listener: BgpListener<Cnx>>(
        &self,
        event_tx: Sender<FsmEvent<Cnx>>,
    ) {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            let listener = Listener::bind(&self.listen).unwrap();
            let conn = match listener.accept(
                self.log.clone(),
                event_tx.clone(),
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

    pub fn add_session(&self, addr: IpAddr, s: Sender<FsmEvent<Cnx>>) {
        self.addr_to_session.lock().unwrap().insert(addr, s);
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

        self.add_session(peer.host.ip(), event_tx.clone());

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
            self.log.clone(),
        ));

        let r = runner.clone();
        spawn(move || {
            r.start();
        });

        self.sessions.lock().unwrap().push(runner.clone());

        runner
    }
}
