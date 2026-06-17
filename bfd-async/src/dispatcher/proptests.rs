// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Model-based property tests for `Dispatcher`'s bookkeeping.
//!
//! These run against a fake [`super::ListenerBackend`] that never binds a real
//! socket, so a random sequence of `ensure`/`remove` operations can be applied
//! deterministically (no runtime, no ports) and checked against a simple
//! reference model after every step.

use super::Dispatcher;
use super::ListenerBackend;
use super::SharedSessions;
use crate::AddPeerError;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use slog::Discard;
use slog::Logger;
use slog::o;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use test_strategy::proptest;
use tokio::task::JoinHandle;

/// A [`ListenerBackend`] that never binds a real socket. It can be told to fail
/// "binding" specific addresses so we can exercise the bind-failure path.
#[derive(Default)]
struct FakeBackend {
    fail_addrs: HashSet<SocketAddr>,
}

impl ListenerBackend for FakeBackend {
    fn spawn(
        &self,
        listen_addr: SocketAddr,
        _sessions: SharedSessions,
        _log: Logger,
    ) -> Result<Option<JoinHandle<()>>, AddPeerError> {
        if self.fail_addrs.contains(&listen_addr) {
            Err(AddPeerError::Bind {
                addr: listen_addr,
                err: std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "fake bind failure",
                ),
            })
        } else {
            // No real socket and no task: the dispatcher only needs the
            // bookkeeping, and a `Listener` holding `None` shuts down as a
            // no-op.
            Ok(None)
        }
    }
}

// Small fixed domains so collisions (shared listeners) and reuse actually occur
// within a short op sequence. The addresses are never bound, so the specific
// IPs/ports are arbitrary.
fn arb_listen_addr() -> impl Strategy<Value = SocketAddr> {
    let addrs = vec![
        "127.0.0.1:3784".parse().unwrap(),
        "127.0.0.1:4784".parse().unwrap(),
        "192.0.2.1:3784".parse().unwrap(),
    ];
    select(addrs)
}

#[derive(Debug, Clone, test_strategy::Arbitrary)]
enum Op {
    Ensure {
        #[strategy(arb_listen_addr())]
        addr: SocketAddr,
        peer: IpAddr,
    },
    Remove {
        peer: IpAddr,
    },
}

/// Reference model: a peer maps to exactly one listen address.
#[derive(Default)]
struct Model {
    peer_to_addr: BTreeMap<IpAddr, SocketAddr>,
}

enum EnsureOutcome {
    Ok,
    PeerExists,
    BindFailed,
}

impl Model {
    fn ensure(
        &mut self,
        addr: SocketAddr,
        peer: IpAddr,
        fail_addrs: &HashSet<SocketAddr>,
    ) -> EnsureOutcome {
        // A peer may only be registered once, regardless of address. This is
        // checked before any bind is attempted.
        if self.peer_to_addr.contains_key(&peer) {
            return EnsureOutcome::PeerExists;
        }
        // A bind only happens when this address has no listener yet.
        let listener_exists = self.peer_to_addr.values().any(|a| *a == addr);
        if !listener_exists && fail_addrs.contains(&addr) {
            return EnsureOutcome::BindFailed;
        }
        self.peer_to_addr.insert(peer, addr);
        EnsureOutcome::Ok
    }

    /// Returns whether removing `peer` should yield a shutdown handle (i.e. it
    /// was the last peer on its listen address).
    fn remove(&mut self, peer: IpAddr) -> bool {
        let Some(addr) = self.peer_to_addr.remove(&peer) else {
            return false;
        };
        !self.peer_to_addr.values().any(|a| *a == addr)
    }

    fn listen_addrs(&self) -> BTreeSet<SocketAddr> {
        self.peer_to_addr.values().copied().collect()
    }
}

fn check_invariants(dispatcher: &Dispatcher, model: &Model) {
    // peer -> listen addr index matches the model exactly.
    let actual_peers: BTreeMap<IpAddr, SocketAddr> = dispatcher
        .peer_to_listen_addr
        .iter()
        .map(|(k, v)| (*k, *v))
        .collect();
    assert_eq!(actual_peers, model.peer_to_addr);

    // There is exactly one listener per distinct in-use listen address.
    let actual_listeners: BTreeSet<SocketAddr> =
        dispatcher.listeners.keys().copied().collect();
    assert_eq!(actual_listeners, model.listen_addrs());

    // Each listener's session map holds exactly the peers the model assigns to
    // that address, and no listener is empty.
    for (addr, listener) in &dispatcher.listeners {
        let actual: BTreeSet<IpAddr> =
            listener.sessions.read().unwrap().keys().copied().collect();
        let expected: BTreeSet<IpAddr> = model
            .peer_to_addr
            .iter()
            .filter(|(_, a)| *a == addr)
            .map(|(p, _)| *p)
            .collect();
        assert_eq!(actual, expected, "session map mismatch for {addr}");
        assert!(!actual.is_empty(), "empty listener for {addr}");
    }
}

fn run(ops: Vec<Op>, fail_addrs: HashSet<SocketAddr>) {
    let backend = Arc::new(FakeBackend {
        fail_addrs: fail_addrs.clone(),
    });
    let mut dispatcher = Dispatcher::with_backend(backend);
    let mut model = Model::default();
    let log = Logger::root(Discard, o!());

    // Hold onto the receivers so the channels behave as they would in
    // production (the sender side lives in the listener's session map).
    let mut rxs = Vec::new();

    for op in ops {
        match op {
            Op::Ensure { addr, peer } => {
                let got = dispatcher.ensure(addr, peer, Arc::default(), &log);
                match model.ensure(addr, peer, &fail_addrs) {
                    EnsureOutcome::Ok => {
                        rxs.push(got.expect("ensure should have succeeded"));
                    }
                    EnsureOutcome::PeerExists => assert!(
                        matches!(
                            got,
                            Err(AddPeerError::PeerExists(p)) if p == peer,
                        ),
                        "expected PeerExists, got {got:?}",
                    ),
                    EnsureOutcome::BindFailed => assert!(
                        matches!(got, Err(AddPeerError::Bind { .. })),
                        "expected Bind error, got {got:?}",
                    ),
                }
            }
            Op::Remove { peer } => {
                let handle = dispatcher.remove(peer);
                assert_eq!(
                    handle.is_some(),
                    model.remove(peer),
                    "remove({peer}) handle presence mismatch",
                );
                // With the fake backend there is no task to await; dropping the
                // handle runs `Listener`'s `Drop` (a no-op for a `None` task).
                drop(handle);
            }
        }
        check_invariants(&dispatcher, &model);
    }
}

#[proptest]
fn state_machine(#[strategy(vec(any::<Op>(), 0..40))] ops: Vec<Op>) {
    run(ops, HashSet::new());
}

#[proptest]
fn state_machine_with_bind_failures(
    #[strategy(vec(any::<Op>(), 0..40))] ops: Vec<Op>,
    #[strategy(proptest::collection::hash_set(arb_listen_addr(), 0..=3))]
    fail_addrs: HashSet<SocketAddr>,
) {
    run(ops, fail_addrs);
}
