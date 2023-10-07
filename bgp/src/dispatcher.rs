use crate::connection::{BgpConnection, BgpListener};
use crate::lock;
use crate::session::FsmEvent;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Dispatcher<Cnx: BgpConnection> {
    pub addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
    shutdown: AtomicBool,
    listen: String,
    log: Logger,
}

impl<Cnx: BgpConnection> Dispatcher<Cnx> {
    pub fn new(
        addr_to_session: Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<Cnx>>>>>,
        listen: String,
        log: Logger,
    ) -> Self {
        Self {
            addr_to_session,
            listen,
            log,
            shutdown: AtomicBool::new(false),
        }
    }
    pub fn run<Listener: BgpListener<Cnx>>(&self) {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                self.shutdown.store(false, Ordering::Release);
                break;
            }
            let listener = match Listener::bind(&self.listen) {
                Ok(l) => l,
                Err(e) => {
                    slog::error!(
                        self.log,
                        "bgp dispatcher failed to listen {e}"
                    );
                    continue;
                }
            };
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
            match lock!(self.addr_to_session).get(&addr) {
                Some(tx) => {
                    if let Err(e) = tx.send(FsmEvent::Connected(conn)) {
                        slog::error!(
                            self.log,
                            "failed to send connected envent to session: {e}",
                        );
                        continue;
                    }
                }
                None => continue,
            }
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}
