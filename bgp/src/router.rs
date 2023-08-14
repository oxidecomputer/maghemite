use crate::connection::{BgpConnection, BgpListener};
use crate::session::FsmEvent;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::Mutex;

pub struct Router<Cnx: BgpConnection> {
    pub listen: String,
    pub addr_to_session: Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>,
}

impl<Cnx: BgpConnection> Router<Cnx> {
    pub fn new(listen: String) -> Router<Cnx> {
        Self {
            listen,
            addr_to_session: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn run<Listener: BgpListener<Cnx>>(&self) {
        loop {
            let listener = Listener::bind(&self.listen).unwrap();
            let conn = listener.accept().unwrap();
            let addr = conn.peer().ip();
            match self.addr_to_session.lock().unwrap().get(&addr) {
                Some(tx) => {
                    tx.send(FsmEvent::Connected(conn)).unwrap();
                }
                None => continue,
            }
        }
    }
}
