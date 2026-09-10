// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Model-based tests over [`InterfaceSm`].
//!
//! The model drives one state machine through arbitrary interleavings of
//! discovery packets, admin requests, action outcomes and clock advances, and
//! feeds every emitted [`Action::Rib`] into a real [`Rib`] so the two cores are
//! exercised against each other.

use super::*;
use crate::protocol::rib::Rib;
use hegel::TestCase;
use hegel::generators as gs;
use std::collections::HashSet;

const SOLICIT_INTERVAL: Duration = Duration::from_millis(1000);
const EXPIRE_THRESHOLD: Duration = Duration::from_millis(3000);
const IP_ADDR_WAIT: Duration = Duration::from_millis(500);
const BIND_RETRY: Duration = Duration::from_millis(1000);
const READY_POLL: Duration = Duration::from_millis(250);

/// Mirrors the state machine's single outstanding exchange operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    ServerStart,
    SelfPull,
    Pull,
    Send,
}

struct Model {
    sm: InterfaceSm,
    rib: Rib,
    now: Instant,

    /// The operation the driver would have in flight.
    op: Option<Op>,
    /// An `Action::ResolveAddr` is outstanding.
    resolving: bool,
    last_solicit: Option<Instant>,
    /// Peer addresses we have ever heard an advertisement from.
    seen_peers: HashSet<Ipv6Addr>,
    /// Addresses the state machine stopped peering with outright. Every route
    /// learned through one of these must be gone from the rib.
    expired: HashSet<Ipv6Addr>,
    /// Addresses replaced in place by a renumbering peer. Expiry only ever
    /// names the current address, so routes via an abandoned one are stranded.
    /// The threaded implementation strands them the same way, so the port
    /// preserves it rather than fixing it here.
    stranded: HashSet<Ipv6Addr>,
}

fn peer_addr(n: u8) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x40 + u16::from(n))
}

fn ifaddr() -> IfAddr {
    IfAddr {
        ifname: "cxgbe0".into(),
        index: 3,
        addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    }
}

fn net(n: u8) -> oxnet::Ipv6Net {
    format!("fd00:{n}::/64").parse().unwrap()
}

fn tunnel(n: u8) -> v3::TunnelOrigin {
    v3::TunnelOrigin {
        overlay_prefix: format!("10.0.{n}.0/24").parse().unwrap(),
        boundary_addr: Ipv6Addr::new(0xfd00, 0x99, 0, 0, 0, 0, 0, 1),
        vni: u32::from(n) + 1,
        metric: 0,
    }
}

impl Model {
    fn new() -> Self {
        let now = Instant::now();
        let config = Config {
            aobj_name: "cxgbe0/ll".into(),
            hostname: "violin".into(),
            kind: RouterKind::Transit,
            solicit_interval: SOLICIT_INTERVAL,
            expire_threshold: EXPIRE_THRESHOLD,
            ip_addr_wait: IP_ADDR_WAIT,
            exchange_bind_retry: BIND_RETRY,
            exchange_ready_poll: READY_POLL,
        };
        Self {
            sm: InterfaceSm::new(config, now),
            rib: Rib::new("violin".into(), RouterKind::Transit),
            now,
            op: None,
            resolving: false,
            last_solicit: None,
            seen_peers: HashSet::new(),
            expired: HashSet::new(),
            stranded: HashSet::new(),
        }
    }

    /// Feed an input and account for every action the way a correct driver
    /// would, asserting the per-action preconditions as it goes.
    fn apply(&mut self, input: Input) {
        let before = self.peer();
        for action in self.sm.handle(input, self.now) {
            match action {
                Action::ResolveAddr => {
                    assert!(!self.resolving, "overlapping address resolution");
                    self.resolving = true;
                }
                // The cadence is a property of the socket, not the process:
                // a freshly opened link solicits immediately.
                Action::OpenSockets(_) => self.last_solicit = None,
                Action::CloseSockets => self.resolving = false,
                Action::StartExchangeServer => self.start(Op::ServerStart),
                Action::SelfPull => self.start(Op::SelfPull),
                Action::PeerPull { peer, .. } => {
                    assert_eq!(
                        self.sm.status().peer.map(|p| p.addr),
                        Some(peer)
                    );
                    self.start(Op::Pull);
                }
                Action::SendUpdate { peer, .. } => {
                    assert_eq!(
                        self.sm.status().peer.map(|p| p.addr),
                        Some(peer)
                    );
                    self.start(Op::Send);
                }
                Action::StopExchangeServer => self.op = None,
                Action::Solicit => {
                    if let Some(last) = self.last_solicit {
                        assert!(
                            self.now.duration_since(last) >= SOLICIT_INTERVAL,
                            "solicited twice inside one interval",
                        );
                    }
                    self.last_solicit = Some(self.now);
                }
                Action::Advertise { .. } => {}
                Action::Rib(event) => {
                    self.rib.apply(event);
                }
            }
        }
        self.track_peer_change(before);
    }

    /// Classify a change of peer as an outright loss or an in-place
    /// replacement. The distinction is what the rib invariant turns on.
    fn track_peer_change(&mut self, before: Option<Ipv6Addr>) {
        let after = self.peer();
        if before == after {
            return;
        }
        if let Some(old) = before {
            if after.is_some() {
                self.stranded.insert(old);
            } else {
                self.expired.insert(old);
            }
        }
        if let Some(new) = after {
            self.expired.remove(&new);
            self.stranded.remove(&new);
        }
    }

    fn start(&mut self, op: Op) {
        assert_eq!(
            self.op, None,
            "started {op:?} with an exchange operation already in flight",
        );
        self.op = Some(op);
    }

    fn peer(&self) -> Option<Ipv6Addr> {
        self.sm.status().peer.map(|p| p.addr)
    }
}

#[hegel::state_machine]
impl Model {
    /// Advance the clock by an arbitrary amount and let deadlines fire.
    #[rule]
    fn tick(&mut self, tc: TestCase) {
        let ms = tc.draw(gs::integers::<u64>().min_value(0).max_value(5_000));
        self.now += Duration::from_millis(ms);
        self.apply(Input::Timer);
    }

    /// Wake exactly when the state machine asked to be woken. The deadline
    /// must then move strictly forward, or a driver would spin.
    #[rule]
    fn tick_to_deadline(&mut self, tc: TestCase) {
        let deadline = self.sm.next_deadline();
        tc.assume(deadline.is_some());
        let deadline = deadline.unwrap();
        assert!(deadline >= self.now, "next_deadline is in the past");

        self.now = deadline;
        self.apply(Input::Timer);

        if let Some(next) = self.sm.next_deadline() {
            assert!(
                next > deadline || self.op.is_some(),
                "deadline did not advance past {deadline:?}",
            );
        }
    }

    #[rule]
    fn resolve_address(&mut self, tc: TestCase) {
        tc.assume(self.resolving);
        let found = tc.draw(gs::booleans());
        self.resolving = false;
        self.apply(Input::Addr(found.then(ifaddr)));
    }

    #[rule]
    fn hear_advertisement(&mut self, tc: TestCase) {
        let which = tc.draw(gs::integers::<u8>().min_value(0).max_value(2));
        // 9 is not a version we speak; it must be dropped, not peered with.
        let version = tc.draw(gs::sampled_from(vec![2u8, 3, 9]));
        let from = peer_addr(which);
        if version == 2 || version == 3 {
            self.seen_peers.insert(from);
        }
        self.apply(Input::Discovery {
            from,
            packet: Discovery::Advertise {
                hostname: format!("piano{which}"),
                kind: RouterKind::Server,
                version,
            },
        });
    }

    /// Run the whole address-and-startup handshake to completion in one step.
    /// The fine-grained rules already cover every way each leg of it can fail;
    /// this exists so the route-bearing states sit one step from the start of a
    /// run rather than five, which is what makes expiry properties reachable.
    #[rule]
    fn establish_peer(&mut self, tc: TestCase) {
        tc.assume(self.op.is_none());
        let which = tc.draw(gs::integers::<u8>().min_value(0).max_value(2));
        let from = peer_addr(which);

        self.resolving = false;
        self.apply(Input::Addr(Some(ifaddr())));
        self.seen_peers.insert(from);
        self.apply(Input::Discovery {
            from,
            packet: Discovery::Advertise {
                hostname: format!("piano{which}"),
                kind: RouterKind::Server,
                version: 3,
            },
        });

        while let Some(op) = self.op {
            self.op = None;
            self.apply(Input::Outcome(match op {
                Op::ServerStart => Outcome::ExchangeServerStarted(true),
                Op::SelfPull => Outcome::SelfPull(true),
                Op::Pull => Outcome::PeerPull(Some(Box::new(v3::Update {
                    underlay: Some(v3::UnderlayUpdate::announce(
                        self.drawn_paths(&tc),
                    )),
                    tunnel: None,
                }))),
                Op::Send => Outcome::UpdateSent(true),
            }));
        }
    }

    #[rule]
    fn hear_solicitation(&mut self, tc: TestCase) {
        let which = tc.draw(gs::integers::<u8>().min_value(0).max_value(2));
        self.apply(Input::Discovery {
            from: peer_addr(which),
            packet: Discovery::Solicit,
        });
    }

    #[rule]
    fn solicit_fails(&mut self, _: TestCase) {
        self.apply(Input::SolicitFailed);
    }

    /// Complete whatever the driver has in flight.
    #[rule]
    fn complete_operation(&mut self, tc: TestCase) {
        let op = self.op;
        tc.assume(op.is_some());
        let ok = tc.draw(gs::booleans());
        self.op = None;
        let outcome = match op.unwrap() {
            Op::ServerStart => Outcome::ExchangeServerStarted(ok),
            Op::SelfPull => Outcome::SelfPull(ok),
            Op::Pull => Outcome::PeerPull(ok.then(|| {
                Box::new(v3::Update {
                    underlay: Some(v3::UnderlayUpdate::announce(
                        self.drawn_paths(&tc),
                    )),
                    tunnel: None,
                })
            })),
            Op::Send => Outcome::UpdateSent(ok),
        };
        self.apply(Input::Outcome(outcome));
    }

    /// An outcome that no longer matches anything in flight must be dropped
    /// rather than acted on.
    #[rule]
    fn stale_outcome(&mut self, tc: TestCase) {
        tc.assume(self.op.is_none());
        let ok = tc.draw(gs::booleans());
        self.apply(Input::Outcome(Outcome::UpdateSent(ok)));
    }

    #[rule]
    fn admin_underlay(&mut self, tc: TestCase) {
        let announce = tc.draw(gs::booleans());
        let prefixes: HashSet<oxnet::Ipv6Net> = self.drawn_prefixes(&tc);
        let set = PrefixSet::Underlay(prefixes);
        self.apply(Input::Admin(if announce {
            AdminEvent::Announce(set)
        } else {
            AdminEvent::Withdraw(set)
        }));
    }

    #[rule]
    fn admin_tunnel(&mut self, tc: TestCase) {
        let announce = tc.draw(gs::booleans());
        let n = tc.draw(gs::integers::<u8>().min_value(0).max_value(3));
        let set = PrefixSet::Tunnel(HashSet::from([tunnel(n)]));
        self.apply(Input::Admin(if announce {
            AdminEvent::Announce(set)
        } else {
            AdminEvent::Withdraw(set)
        }));
    }

    #[rule]
    fn admin_sync(&mut self, _: TestCase) {
        self.apply(Input::Admin(AdminEvent::Sync));
    }

    #[rule]
    fn admin_expire(&mut self, tc: TestCase) {
        let which = tc.draw(gs::integers::<u8>().min_value(0).max_value(2));
        self.apply(Input::Admin(AdminEvent::Expire(peer_addr(which))));
    }

    #[rule]
    fn peer_pushes(&mut self, tc: TestCase) {
        let paths = self.drawn_paths(&tc);
        self.apply(Input::PeerPush(Box::new(v3::Update {
            underlay: Some(v3::UnderlayUpdate::announce(paths)),
            tunnel: None,
        })));
    }

    #[rule]
    fn peer_withdraws(&mut self, tc: TestCase) {
        let paths = self.drawn_paths(&tc);
        self.apply(Input::PeerPush(Box::new(v3::Update {
            underlay: Some(v3::UnderlayUpdate::withdraw(paths)),
            tunnel: None,
        })));
    }

    #[rule]
    fn hub_redistributes(&mut self, tc: TestCase) {
        let paths = self.drawn_paths(&tc);
        self.apply(Input::Redistribute(Box::new(v3::Update {
            underlay: Some(v3::UnderlayUpdate::announce(paths)),
            tunnel: None,
        })));
    }

    /// Exchange is only reachable with a peer, and the peer identity the admin
    /// API reports is the one sends are addressed to.
    #[invariant]
    fn exchange_implies_a_peer(&self, _: TestCase) {
        let status = self.sm.status();
        if status.state == FsmState::Exchange {
            assert!(status.peer.is_some(), "in exchange with no peer identity",);
        }
    }

    /// Before an address resolves there is no peering and nothing to report.
    #[invariant]
    fn init_is_quiescent(&self, _: TestCase) {
        let status = self.sm.status();
        if status.state == FsmState::Init {
            assert_eq!(status.peer, None);
            assert!(status.if_name.is_empty());
            assert_eq!(status.if_index, 0);
        }
    }

    /// Losing a peer withdraws everything learned through it, on every path
    /// out of exchange: a send failure, a discovery expiry, a failed solicit
    /// and an administrative expire all have to reach the rib.
    #[invariant(always_run)]
    fn expiry_clears_the_rib(&self, _: TestCase) {
        for route in self.rib.imported() {
            assert!(
                !self.expired.contains(&route.nexthop)
                    || self.stranded.contains(&route.nexthop),
                "route to {} via {} survived the loss of that peer",
                route.destination,
                route.nexthop,
            );
        }
        for route in self.rib.imported_tunnel() {
            assert!(
                !self.expired.contains(&route.nexthop)
                    || self.stranded.contains(&route.nexthop),
                "tunnel endpoint via {} survived the loss of that peer",
                route.nexthop,
            );
        }
    }

    /// Nothing is ever learned through an address that never advertised.
    #[invariant]
    fn routes_come_from_real_peers(&self, _: TestCase) {
        for route in self.rib.imported() {
            assert!(
                self.seen_peers.contains(&route.nexthop),
                "route via unknown nexthop {}",
                route.nexthop,
            );
        }
    }

    /// A peer must be established before it can expire.
    #[invariant]
    fn expirations_trail_establishments(&self, _: TestCase) {
        let c = self.sm.counters();
        assert!(
            c.peer_expirations <= c.peer_established,
            "{} expirations for {} establishments",
            c.peer_expirations,
            c.peer_established,
        );
    }
}

impl Model {
    fn drawn_prefixes(&self, tc: &TestCase) -> HashSet<oxnet::Ipv6Net> {
        let n = tc.draw(gs::integers::<u8>().min_value(0).max_value(3));
        HashSet::from([net(n)])
    }

    fn drawn_paths(&self, tc: &TestCase) -> HashSet<v3::PathVector> {
        let n = tc.draw(gs::integers::<u8>().min_value(0).max_value(3));
        HashSet::from([v3::PathVector {
            destination: net(n),
            path: vec!["cello".into()],
        }])
    }
}

#[hegel::test]
fn interface_state_machine(tc: TestCase) {
    hegel::stateful::run(Model::new(), tc);
}
