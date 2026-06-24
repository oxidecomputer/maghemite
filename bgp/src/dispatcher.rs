// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    IO_TIMEOUT,
    connection::{BgpConnection, BgpListener},
    router::SessionMap,
    session::{FsmEvent, SessionEvent},
};
use mg_common::lock;
use slog::{Logger, debug, error, info, warn};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};
use unnumbered::BgpUnnumbered;

const UNIT_DISPATCHER: &str = "dispatcher";

pub struct Dispatcher<Cnx: BgpConnection + 'static> {
    /// Session map shared with all Routers, indexed by PeerId.
    pub sessions: Arc<Mutex<SessionMap<Cnx>>>,

    /// Optional unnumbered neighbor manager for link-local connection routing.
    /// When present, enables routing of IPv6 link-local connections to
    /// unnumbered sessions based on interface scope_id
    unnumbered_manager: Option<Arc<dyn BgpUnnumbered>>,

    shutdown: AtomicBool,
    listen: String,
    log: Mutex<Logger>,
}

impl<Cnx: BgpConnection + 'static> Dispatcher<Cnx> {
    pub fn new(
        sessions: Arc<Mutex<SessionMap<Cnx>>>,
        listen: String,
        log: Logger,
        unnumbered_manager: Option<Arc<dyn BgpUnnumbered>>,
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
                    self.sessions.clone(),
                    IO_TIMEOUT,
                ) {
                    Ok(accepted) => {
                        debug!(log,
                            "accepted inbound connection from: {}", accepted.connection.peer();
                            "peer" => accepted.connection.peer(),
                        );
                        accepted
                    }
                    Err(crate::error::Error::Timeout) => {
                        continue 'accept;
                    }
                    Err(e) => {
                        error!(log, "listener accept error: {e}");
                        continue 'listener;
                    }
                };

                let peer_addr = accepted.connection.peer();
                let session_log = log.new(slog::o!(
                    "peer" => peer_addr,
                    "session_key" => format!("{:?}", accepted.session_key),
                ));

                if let Err(e) = Listener::apply_policy(
                    &accepted.connection,
                    accepted.min_ttl,
                    accepted.md5_key,
                ) {
                    warn!(session_log,
                        "failed to apply policy for connection";
                        "error" => format!("{e}")
                    );
                }

                if let Err(e) =
                    accepted.runner.event_tx.send(FsmEvent::Session(
                        SessionEvent::TcpConnectionAcked(accepted.connection),
                    ))
                {
                    error!(session_log,
                        "failed to send connected event to session";
                        "error" => format!("{e}")
                    );
                    continue 'listener;
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

impl<Cnx: BgpConnection + 'static> Drop for Dispatcher<Cnx> {
    fn drop(&mut self) {
        debug!(lock!(self.log), "dropping dispatcher");
    }
}

#[cfg(test)]
mod tests {
    use crate::{connection::resolve_session_key, session::PeerId};
    use slog::Logger;
    use std::sync::Arc;
    use unnumbered::{BgpUnnumbered, NdpNeighbor, UnnumberedError};

    struct TestUnnumbered {
        scope_result: Result<Option<String>, UnnumberedError>,
    }

    impl BgpUnnumbered for TestUnnumbered {
        fn get_active_interface_by_scope(
            &self,
            _scope_id: u32,
        ) -> Result<Option<String>, UnnumberedError> {
            self.scope_result.clone()
        }

        fn get_discovered_ndp_neighbor(
            &self,
            _interface: &str,
        ) -> Result<Option<NdpNeighbor>, UnnumberedError> {
            Ok(None)
        }
    }

    fn log() -> Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    fn unnumbered_manager(
        scope_result: Result<Option<String>, UnnumberedError>,
    ) -> Arc<dyn BgpUnnumbered> {
        Arc::new(TestUnnumbered { scope_result })
    }

    #[test]
    fn link_local_scope_resolves_to_interface_session_key() {
        let manager = unnumbered_manager(Ok(Some("eth0".into())));
        let peer = "[fe80::1%7]:179".parse().unwrap();

        let key = resolve_session_key(peer, Some(&manager), &log());

        assert_eq!(key, PeerId::Interface("eth0".into()));
    }

    #[test]
    fn link_local_without_active_scope_falls_back_to_ip_session_key() {
        let manager = unnumbered_manager(Ok(None));
        let peer = "[fe80::1%7]:179".parse().unwrap();

        let key = resolve_session_key(peer, Some(&manager), &log());

        assert_eq!(key, PeerId::Ip(peer.ip()));
    }

    #[test]
    fn link_local_resolution_error_falls_back_to_ip_session_key() {
        let manager =
            unnumbered_manager(Err(UnnumberedError::ResolutionFailed {
                interface: "eth0".into(),
                reason: "boom".into(),
            }));
        let peer = "[fe80::1%7]:179".parse().unwrap();

        let key = resolve_session_key(peer, Some(&manager), &log());

        assert_eq!(key, PeerId::Ip(peer.ip()));
    }

    #[test]
    fn non_link_local_address_uses_ip_session_key() {
        let manager = unnumbered_manager(Ok(Some("eth0".into())));
        let peer = "[2001:db8::1]:179".parse().unwrap();

        let key = resolve_session_key(peer, Some(&manager), &log());

        assert_eq!(key, PeerId::Ip(peer.ip()));
    }
}
