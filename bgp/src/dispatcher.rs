// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    IO_TIMEOUT,
    connection::{BgpConnection, BgpListener},
    log::dispatcher_log,
    session::{FsmEvent, PeerId, SessionEndpoint, SessionEvent},
    unnumbered::UnnumberedManager,
};
use mg_common::lock;
use slog::Logger;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

const UNIT_DISPATCHER: &str = "dispatcher";

pub struct Dispatcher<Cnx: BgpConnection> {
    /// Session endpoint map indexed by PeerId (IP or interface name)
    /// This unified map supports both numbered and unnumbered BGP sessions
    pub peer_to_session: Arc<Mutex<BTreeMap<PeerId, SessionEndpoint<Cnx>>>>,

    /// Optional unnumbered neighbor manager for link-local connection routing.
    /// When present, enables routing of IPv6 link-local connections to
    /// unnumbered sessions based on interface scope_id
    unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,

    shutdown: AtomicBool,
    listen: String,
    log: Logger,
}

impl<Cnx: BgpConnection + 'static> Dispatcher<Cnx> {
    pub fn new(
        peer_to_session: Arc<Mutex<BTreeMap<PeerId, SessionEndpoint<Cnx>>>>,
        listen: String,
        log: Logger,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Self {
        Self {
            peer_to_session,
            unnumbered_manager,
            listen,
            log,
            shutdown: AtomicBool::new(false),
        }
    }

    /// Resolve incoming peer address to appropriate PeerId.
    ///
    /// For IPv6 link-local addresses with an unnumbered manager, attempts to
    /// resolve scope_id to interface name for interface-based routing.
    /// Falls back to IP-based routing for all other cases.
    fn resolve_session_key(&self, peer_addr: SocketAddr) -> PeerId {
        // Try interface-based routing for IPv6 link-local addresses
        if let Some(ref mgr) = self.unnumbered_manager
            && let SocketAddr::V6(v6_addr) = peer_addr
            && v6_addr.ip().is_unicast_link_local()
        {
            let scope_id = v6_addr.scope_id();
            if let Some(interface) = mgr.get_interface_for_scope(scope_id) {
                dispatcher_log!(self,
                    debug,
                    "routing link-local connection to interface session";
                    "peer" => format!("{}", peer_addr),
                    "scope_id" => scope_id,
                    "interface" => &interface,
                    "listen_address" => &self.listen
                );
                return PeerId::Interface(interface);
            }
            dispatcher_log!(self,
                debug,
                "no interface mapping for link-local scope_id, using IP lookup";
                "peer" => format!("{}", peer_addr),
                "scope_id" => scope_id,
                "listen_address" => &self.listen
            );
        }

        // Default to IP-based routing
        PeerId::Ip(peer_addr.ip())
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
            let listener = match Listener::bind(
                &self.listen,
                self.unnumbered_manager.clone(),
            ) {
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
                    self.peer_to_session.clone(),
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

                let peer_addr = accepted.peer();
                let key = self.resolve_session_key(peer_addr);

                match lock!(self.peer_to_session).get(&key).cloned() {
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
                                "failed to apply policy for connection from {}: {e}", peer_addr;
                                "listen_address" => &self.listen,
                                "peer" => format!("{}", peer_addr),
                                "session_key" => format!("{:?}", key),
                                "error" => format!("{e}")
                            );
                        }

                        if let Err(e) =
                            session_endpoint.event_tx.send(FsmEvent::Session(
                                SessionEvent::TcpConnectionAcked(accepted),
                            ))
                        {
                            dispatcher_log!(self,
                                error,
                                "failed to send connected event to session for {}: {e}", peer_addr;
                                "listen_address" => &self.listen,
                                "peer" => format!("{}", peer_addr),
                                "session_key" => format!("{:?}", key)
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

    pub fn listen_addr(&self) -> &str {
        &self.listen
    }

    pub fn shutdown(&self) {
        dispatcher_log!(self, info,
            "dispatcher received shutdown request, setting shutdown flag";
            "listen_address" => &self.listen
        );
        self.shutdown.store(true, Ordering::Release);
    }
}

impl<Cnx: BgpConnection> Drop for Dispatcher<Cnx> {
    fn drop(&mut self) {
        dispatcher_log!(self,
            debug,
            "dropping dispatcher with listen_addr {}",
            &self.listen;
            "listen_address" => &self.listen
        );
    }
}
