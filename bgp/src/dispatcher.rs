// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::{BgpConnection, BgpListener};
use crate::log::dispatcher_log;
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

const UNIT_DISPATCHER: &str = "dispatcher";

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
                dispatcher_log!(self,
                    info,
                    "shutting down";
                    "listen_address" => &self.listen
                );
                self.shutdown.store(false, Ordering::Release);
                break 'listener;
            }
            dispatcher_log!(self,
                debug,
                "listener bind: {}", &self.listen;
                "listen_address" => &self.listen
            );
            let listener = match Listener::bind(&self.listen) {
                Ok(l) => l,
                Err(e) => {
                    dispatcher_log!(self,
                        error,
                        "listener bind error: {e}";
                        "listen_address" => &self.listen
                    );
                    sleep(Duration::from_secs(1));
                    continue 'listener;
                }
            };
            'accept: loop {
                let accepted = match listener.accept(
                    self.log.clone(),
                    UNIT_DISPATCHER,
                    self.addr_to_session.clone(),
                    Duration::from_millis(100),
                ) {
                    Ok(c) => {
                        dispatcher_log!(self,
                            debug,
                            "accepted inbound connection from: {}", c.peer();
                            "peer" => c.peer(),
                            "listen_address" => &self.listen
                        );
                        c
                    }
                    Err(crate::error::Error::Timeout) => {
                        continue 'accept;
                    }
                    Err(e) => {
                        dispatcher_log!(self,
                            error,
                            "listener accept error: {e}";
                            "listen_address" => &self.listen
                        );
                        continue 'listener;
                    }
                };
                let addr = accepted.peer().ip();
                match lock!(self.addr_to_session).get(&addr) {
                    Some(tx) => {
                        if let Err(e) = tx.send(FsmEvent::Connected(accepted)) {
                            dispatcher_log!(self,
                                error,
                                "failed to send connected event to session for {addr}: {e}";
                                "listen_address" => &self.listen,
                                "address" => format!("{addr}")
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
