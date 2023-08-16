use crate::config::RouterConfig;
use crate::connection::{BgpConnection, BgpListener};
use crate::session::FsmEvent;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::Mutex;

pub struct Router<Cnx: BgpConnection> {
    pub config: RouterConfig,
    pub listen: String,
    pub addr_to_session: Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>,
    pub log: Logger,
}

impl<Cnx: BgpConnection> Router<Cnx> {
    pub fn new(
        listen: String,
        config: RouterConfig,
        log: Logger,
    ) -> Router<Cnx> {
        Self {
            config,
            listen,
            addr_to_session: Mutex::new(BTreeMap::new()),
            log,
        }
    }

    pub fn run<Listener: BgpListener<Cnx>>(
        &self,
        event_tx: Sender<FsmEvent<Cnx>>,
    ) {
        loop {
            let listener = Listener::bind(&self.listen).unwrap();
            let conn =
                listener.accept(self.log.clone(), event_tx.clone()).unwrap();
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
