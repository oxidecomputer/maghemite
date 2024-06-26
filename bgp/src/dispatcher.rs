// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::{BgpConnection, BgpListener};
use crate::session::FsmEvent;
use mg_common::lock;
use slog::Logger;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
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
                    sleep(Duration::from_secs(1));
                    continue;
                }
            };
            let accepted = match listener.accept(
                self.log.clone(),
                self.addr_to_session.clone(),
                Duration::from_millis(100),
            ) {
                Ok(c) => c,
                Err(crate::error::Error::Timeout) => {
                    continue;
                }
                Err(e) => {
                    slog::error!(self.log, "accept error: {e}");
                    continue;
                }
            };
            let addr = accepted.peer().ip();
            match lock!(self.addr_to_session).get(&addr) {
                Some(tx) => {
                    if let Err(e) = tx.send(FsmEvent::Connected(accepted)) {
                        slog::error!(
                            self.log,
                            "failed to send connected event to session: {e}",
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
