use crate::config::RouterConfig;
use crate::connection::{BgpConnection, BgpListener};
use crate::session::FsmEvent;
use rdb::Db;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::Duration;

pub struct Router<Cnx: BgpConnection> {
    pub config: RouterConfig,
    pub listen: String,
    pub addr_to_session: Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>,
    pub log: Logger,
    pub shutdown: AtomicBool,
    pub db: Db,
}

impl<Cnx: BgpConnection> Router<Cnx> {
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
}
