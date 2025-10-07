// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    connection::{BgpConnection, BgpListener},
    log::dispatcher_log,
    session::{FsmEvent, SessionEndpoint, SessionEvent},
    IO_TIMEOUT,
};
use mg_common::lock;
use slog::Logger;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

const UNIT_DISPATCHER: &str = "dispatcher";

pub struct Dispatcher<Cnx: BgpConnection> {
    pub addr_to_session: Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>>,
    shutdown: AtomicBool,
    listen: String,
    log: Logger,
}

impl<Cnx: BgpConnection + 'static> Dispatcher<Cnx> {
    pub fn new(
        addr_to_session: Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>>,
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
        dispatcher_log!(self,
            info,
            "dispatcher started";
            "listen_address" => &self.listen
        );
        'listener: loop {
            // We need to check the shutdown flag in the listener loop so we can
            // still return even if bind() keeps failing and we're stuck
            if self.shutdown.load(Ordering::Acquire) {
                dispatcher_log!(self,
                    info,
                    "dispatcher caught shutdown flag from listener loop";
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
                    // XXX: possible death loop?
                    continue 'listener;
                }
            };
            'accept: loop {
                // We also need to check the shutdown flag inside the accept
                // loop, because we won't restart the listener loop unless we've
                // encountered an error indicating we can't just call accept()
                // again and we need a whole new listener.
                if self.shutdown.load(Ordering::Acquire) {
                    dispatcher_log!(self,
                        info,
                        "dispatcher caught shutdown flag from accept loop";
                        "listen_address" => &self.listen
                    );
                    self.shutdown.store(false, Ordering::Release);
                    break 'listener;
                }

                let accepted = match listener.accept(
                    self.log.clone(),
                    self.addr_to_session.clone(),
                    IO_TIMEOUT,
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
                match lock!(self.addr_to_session).get(&addr).cloned() {
                    Some(session_endpoint) => {
                        // Apply connection policy from the session configuration
                        let min_ttl = lock!(session_endpoint.config).min_ttl;
                        let md5_key =
                            lock!(session_endpoint.config).md5_auth_key.clone();

                        if let Err(e) =
                            Listener::apply_policy(&accepted, min_ttl, md5_key)
                        {
                            dispatcher_log!(self,
                                warn,
                                "failed to apply policy for connection from {addr}: {e}";
                                "listen_address" => &self.listen,
                                "address" => format!("{addr}"),
                                "error" => format!("{e}")
                            );
                        }

                        if let Err(e) =
                            session_endpoint.event_tx.send(FsmEvent::Session(
                                SessionEvent::Connected(accepted),
                            ))
                        {
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
        dispatcher_log!(self,
            info,
            "dispatcher shutdown complete";
            "listen_address" => &self.listen
        );
    }

    pub fn shutdown(&self) {
        dispatcher_log!(self, info,
            "dispatcher received shutdown request, setting shutdown flag";
            "listen_address" => &self.listen
        );
        self.shutdown.store(true, Ordering::Release);
    }
}
