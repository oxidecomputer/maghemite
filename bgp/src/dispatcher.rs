// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::{BgpConnection, BgpListener};
use crate::session::FsmEvent;
use mg_common::lock;
use slog::{debug, Logger};
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
        'listener: loop {
            if self.shutdown.load(Ordering::Acquire) {
                self.shutdown.store(false, Ordering::Release);
                break 'listener;
            }
            debug!(self.log, "bgp dispatcher binding {}", &self.listen);
            let listener = match Listener::bind(&self.listen) {
                Ok(l) => l,
                Err(e) => {
                    slog::error!(self.log, "bgp listener failed to bind: {e}");
                    sleep(Duration::from_secs(1));
                    continue 'listener;
                }
            };
            'accept: loop {
                let accepted = match listener.accept(
                    self.log.clone(),
                    self.addr_to_session.clone(),
                    Duration::from_millis(100),
                ) {
                    Ok(c) => {
                        slog::debug!(
                            self.log,
                            "accepted connection from {}",
                            c.peer()
                        );
                        c
                    }
                    Err(crate::error::Error::Timeout) => {
                        continue 'accept;
                    }
                    Err(e) => {
                        slog::error!(self.log, "accept error: {e}");
                        continue 'listener;
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
                            continue 'listener;
                        }
                    }
                    None => continue 'accept,
                }
            }
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}
