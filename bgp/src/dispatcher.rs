// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    IO_TIMEOUT,
    connection::{BgpConnection, BgpListener, ListenerAcceptError},
    router::SessionMap,
    session::{FsmEvent, PeerId, SessionEvent},
    unnumbered::UnnumberedManager,
};
use mg_common::lock;
use slog::{Logger, debug, error, info, warn};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};

const UNIT_DISPATCHER: &str = "dispatcher";

/// Why the dispatcher stopped serving a listener.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AcceptLoopExit {
    Shutdown,
    Rebind,
}

pub struct Dispatcher<Cnx: BgpConnection + 'static> {
    /// Session map shared with all Routers, indexed by PeerId.
    pub sessions: Arc<Mutex<SessionMap<Cnx>>>,

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
        sessions: Arc<Mutex<SessionMap<Cnx>>>,
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
            sessions,
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
        let log = lock!(self.log).clone();
        info!(log, "dispatcher started");

        loop {
            info!(log, "starting listener with bind arg: {}", &self.listen);

            // We need to check the shutdown flag in the listener loop so we can
            // still return even if bind() keeps failing and we're stuck
            if self.shutdown.load(Ordering::Acquire) {
                info!(
                    log,
                    "dispatcher caught shutdown flag from listener loop"
                );
                self.shutdown.store(false, Ordering::Release);
                break;
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
                    continue;
                }
            };

            match self.accept_loop(listener) {
                AcceptLoopExit::Shutdown => break,
                AcceptLoopExit::Rebind => continue,
            }
        }
        info!(log, "dispatcher shutdown complete");
    }

    /// Serve one listener until shutdown or a request to bind a replacement.
    pub(crate) fn accept_loop<Listener: BgpListener<Cnx>>(
        &self,
        listener: Listener,
    ) -> AcceptLoopExit {
        let log = lock!(self.log).clone();
        // If the user requested to bind on port 0, a random port will be
        // selected, so we capture the port in the logger context after the
        // listener has been started
        let bound_log = log.new(slog::o!("bind_addr" => listener.bind_addr()));

        info!(bound_log, "transitioning to accept loop");
        loop {
            // We also need to check the shutdown flag inside the accept
            // loop, because we won't restart the listener loop unless we've
            // encountered an error indicating we can't just call accept()
            // again and we need a whole new listener.
            if self.shutdown.load(Ordering::Acquire) {
                info!(
                    bound_log,
                    "dispatcher caught shutdown flag from accept loop"
                );
                self.shutdown.store(false, Ordering::Release);
                return AcceptLoopExit::Shutdown;
            }

            let accepted = match listener.accept(
                bound_log.clone(),
                self.sessions.clone(),
                IO_TIMEOUT,
            ) {
                Ok(conn) => {
                    debug!(bound_log,
                        "accepted inbound connection from: {}", conn.peer();
                        "peer" => conn.peer(),
                    );
                    conn
                }
                Err(ListenerAcceptError::Timeout) => {
                    // accept() timed out before a new connection arrived.
                    // This is expected, carry on.
                    continue;
                }
                Err(ListenerAcceptError::UnknownPeer(peer)) => {
                    // Inbound connection attempt from a peer we haven't
                    // configured (either via IP or ifname). Carry on.
                    debug!(
                        bound_log,
                        "rejecting connection from unknown peer: {peer}"
                    );
                    continue;
                }
                Err(ListenerAcceptError::NewConnectionSetup(e)) => {
                    // We successfully accept()'d a new connection, but we
                    // failed to apply requisite connection settings e.g.
                    // disabling non-blocking or setting TCP_NODELAY.
                    // Log and carry on.
                    warn!(bound_log, "accepted connection setup error: {e}");
                    continue;
                }
                Err(ListenerAcceptError::Listener(e)) => {
                    // There has been an error on the listener itself and we
                    // need to replace it with a new one. Break out of the
                    // accept loop so we can create a new listener.
                    error!(bound_log, "listener accept error: {e}");
                    return AcceptLoopExit::Rebind;
                }
            };

            let peer_addr = accepted.peer();
            let key = self.resolve_session_key(peer_addr);
            let session_log = bound_log.new(slog::o!(
                "peer" => peer_addr,
                "session_key" => format!("{key:?}"),
            ));

            let (runner, min_ttl, md5_key) = {
                let sessions = lock!(self.sessions);
                let Some(runner) = sessions.get(&key).cloned() else {
                    debug!(
                        session_log,
                        "no session found for peer, dropping connection"
                    );
                    continue;
                };
                let config = lock!(runner.session);
                (runner.clone(), config.min_ttl, config.md5_auth_key.clone())
            };

            if let Err(e) = Listener::apply_policy(&accepted, min_ttl, md5_key)
            {
                warn!(session_log,
                    "failed to apply policy for connection";
                    "error" => format!("{e}")
                );
            }

            if let Err(e) = runner.event_tx.send(FsmEvent::Session(
                SessionEvent::TcpConnectionAcked(accepted),
            )) {
                error!(session_log,
                    "failed to send connected event to session";
                    "error" => format!("{e}")
                );
                return AcceptLoopExit::Rebind;
            }
        }
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

impl<Cnx: BgpConnection + 'static> Drop for Dispatcher<Cnx> {
    fn drop(&mut self) {
        debug!(lock!(self.log), "dropping dispatcher");
    }
}
