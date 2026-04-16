// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    IO_TIMEOUT,
    connection::{BgpConnection, BgpListener},
    session::{FsmEvent, PeerId, SessionEndpoint, SessionEvent},
    unnumbered::UnnumberedManager,
};
use mg_common::lock;
use slog::{Logger, debug, error, info, warn};
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
    log: Mutex<Logger>,
}

impl<Cnx: BgpConnection + 'static> Dispatcher<Cnx> {
    pub fn new(
        peer_to_session: Arc<Mutex<BTreeMap<PeerId, SessionEndpoint<Cnx>>>>,
        listen: String,
        log: Logger,
        unnumbered_manager: Option<Arc<dyn UnnumberedManager>>,
    ) -> Self {
        let log = log.new(slog::o!(
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_DISPATCHER,
        ));

        Self {
            peer_to_session,
            unnumbered_manager,
            listen,
            log: Mutex::new(log),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Try to resolve peer address to an unnumbered interface.
    ///
    /// Returns `Some(PeerId::Interface)` if:
    /// - We have an unnumbered manager
    /// - The peer address is IPv6 link-local
    /// - We have an interface configured for this scope_id
    /// - The interface is active on the system
    fn try_resolve_unnumbered(&self, peer_addr: SocketAddr) -> Option<PeerId> {
        let mgr = self.unnumbered_manager.as_ref()?;
        let v6_addr = match peer_addr {
            SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => v6,
            _ => return None,
        };
        let interface = mgr.get_interface_by_scope(v6_addr.scope_id())?;
        if mgr.interface_is_active(&interface) {
            Some(PeerId::Interface(interface))
        } else {
            None
        }
    }

    /// Resolve incoming peer address to appropriate PeerId.
    ///
    /// For IPv6 link-local addresses, attempts interface-based routing via
    /// unnumbered manager. Falls back to IP-based routing otherwise.
    fn resolve_session_key(&self, peer_addr: SocketAddr) -> PeerId {
        self.try_resolve_unnumbered(peer_addr)
            .unwrap_or_else(|| PeerId::Ip(peer_addr.ip()))
    }

    pub fn run<Listener: BgpListener<Cnx>>(&self) {
        let mut log = lock!(self.log).clone();
        info!(log, "dispatcher started");

        'listener: loop {
            info!(log, "starting listener with bind arg: {}", &self.listen);

            // We need to check the shutdown flag in the listener loop so we can
            // still return even if bind() keeps failing and we're stuck
            if self.shutdown.load(Ordering::Acquire) {
                info!(
                    log,
                    "dispatcher caught shutdown flag from listener loop"
                );
                self.shutdown.store(false, Ordering::Release);
                break 'listener;
            }

            let listener = match Listener::bind(
                &self.listen,
                log.clone(),
                self.unnumbered_manager.clone(),
            ) {
                Ok(l) => l,
                Err(e) => {
                    error!(log, "listener bind error: {e}");
                    sleep(Duration::from_secs(1));
                    // XXX: possible death loop?
                    continue 'listener;
                }
            };

            // If the user requested to bind on port 0, a random port will be selected,
            // so we capture the port in the logger context after the listener has been
            // started
            let bound_log =
                log.new(slog::o!("bind_addr" => listener.bind_addr()));
            *lock!(self.log) = bound_log.clone();
            log = bound_log;

            info!(log, "transitioning to accept loop");
            'accept: loop {
                // We also need to check the shutdown flag inside the accept
                // loop, because we won't restart the listener loop unless we've
                // encountered an error indicating we can't just call accept()
                // again and we need a whole new listener.
                if self.shutdown.load(Ordering::Acquire) {
                    info!(
                        log,
                        "dispatcher caught shutdown flag from accept loop"
                    );
                    self.shutdown.store(false, Ordering::Release);
                    break 'listener;
                }

                let accepted = match listener.accept(
                    log.clone(),
                    self.peer_to_session.clone(),
                    IO_TIMEOUT,
                ) {
                    Ok(c) => {
                        debug!(log,
                            "accepted inbound connection from: {}", c.peer();
                            "peer" => c.peer(),
                        );
                        c
                    }
                    Err(crate::error::Error::Timeout) => {
                        continue 'accept;
                    }
                    Err(e) => {
                        error!(log, "listener accept error: {e}");
                        continue 'listener;
                    }
                };

                let peer_addr = accepted.peer();
                let key = self.resolve_session_key(peer_addr);
                let session_log = log.new(slog::o!(
                    "peer" => peer_addr,
                    "session_key" => format!("{key:?}"),
                ));

                match lock!(self.peer_to_session).get(&key).cloned() {
                    Some(session_endpoint) => {
                        // Apply connection policy from the session configuration
                        let min_ttl = lock!(session_endpoint.config).min_ttl;
                        let md5_key =
                            lock!(session_endpoint.config).md5_auth_key.clone();

                        if let Err(e) =
                            Listener::apply_policy(&accepted, min_ttl, md5_key)
                        {
                            warn!(session_log,
                                "failed to apply policy for connection";
                                "error" => format!("{e}")
                            );
                        }

                        if let Err(e) =
                            session_endpoint.event_tx.send(FsmEvent::Session(
                                SessionEvent::TcpConnectionAcked(accepted),
                            ))
                        {
                            error!(session_log,
                                "failed to send connected event to session";
                                "error" => format!("{e}")
                            );
                            continue 'listener;
                        }
                    }
                    None => {
                        debug!(
                            session_log,
                            "no session found for peer, dropping connection"
                        );
                        continue 'accept;
                    }
                }
            }
        }
        info!(log, "dispatcher shutdown complete");
    }

    pub fn listen_addr(&self) -> &str {
        &self.listen
    }

    pub fn shutdown(&self) {
        info!(
            lock!(self.log),
            "dispatcher received shutdown request, setting shutdown flag"
        );
        self.shutdown.store(true, Ordering::Release);
    }
}

impl<Cnx: BgpConnection> Drop for Dispatcher<Cnx> {
    fn drop(&mut self) {
        debug!(lock!(self.log), "dropping dispatcher");
    }
}
