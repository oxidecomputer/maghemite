// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use pretty_assertions::assert_eq;
use std::collections::HashSet;

const SOLICIT_INTERVAL: Duration = Duration::from_millis(1000);
const EXPIRE_THRESHOLD: Duration = Duration::from_millis(3000);
const IP_ADDR_WAIT: Duration = Duration::from_millis(500);
const BIND_RETRY: Duration = Duration::from_millis(1000);
const READY_POLL: Duration = Duration::from_millis(250);

fn config() -> Config {
    Config {
        aobj_name: "cxgbe0/ll".into(),
        hostname: "violin".into(),
        kind: RouterKind::Server,
        solicit_interval: SOLICIT_INTERVAL,
        expire_threshold: EXPIRE_THRESHOLD,
        ip_addr_wait: IP_ADDR_WAIT,
        exchange_bind_retry: BIND_RETRY,
        exchange_ready_poll: READY_POLL,
    }
}

fn ifaddr() -> IfAddr {
    IfAddr {
        ifname: "cxgbe0".into(),
        index: 3,
        addr: "fe80::1".parse().unwrap(),
    }
}

fn peer_addr() -> Ipv6Addr {
    "fe80::47".parse().unwrap()
}

fn advertise(from: Ipv6Addr) -> Input {
    Input::Discovery {
        from,
        packet: Discovery::Advertise {
            hostname: "piano".into(),
            kind: RouterKind::Transit,
            version: 3,
        },
    }
}

fn net(n: u8) -> oxnet::Ipv6Net {
    format!("fd00:{n}::/64").parse().unwrap()
}

/// A state machine at `t0` that has resolved its address and is soliciting.
fn soliciting(t0: Instant) -> InterfaceSm {
    let mut sm = InterfaceSm::new(config(), t0);
    assert_eq!(sm.handle(Input::Timer, t0), vec![Action::ResolveAddr]);
    let actions = sm.handle(Input::Addr(Some(ifaddr())), t0);
    assert_eq!(
        actions,
        vec![Action::OpenSockets(ifaddr()), Action::Solicit]
    );
    assert_eq!(sm.status().state, FsmState::Solicit);
    sm
}

/// A state machine at `t0` that is peered and fully in exchange, with the
/// initial pull complete.
fn exchanging(t0: Instant) -> InterfaceSm {
    let mut sm = soliciting(t0);
    assert_eq!(
        sm.handle(advertise(peer_addr()), t0),
        vec![Action::StartExchangeServer]
    );
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::ExchangeServerStarted(true)), t0),
        vec![Action::SelfPull]
    );
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::SelfPull(true)), t0),
        vec![Action::PeerPull {
            peer: peer_addr(),
            version: Version::V3,
        }]
    );
    let actions =
        sm.handle(Input::Outcome(Outcome::PeerPull(Some(Box::default()))), t0);
    assert!(matches!(
        actions[..],
        [Action::Rib(RibEvent::Update { .. })]
    ));
    assert_eq!(sm.status().state, FsmState::Exchange);
    sm
}

#[test]
fn resolve_retries_until_an_address_appears() {
    let t0 = Instant::now();
    let mut sm = InterfaceSm::new(config(), t0);

    assert_eq!(sm.handle(Input::Timer, t0), vec![Action::ResolveAddr]);

    // A resolve is outstanding, so nothing is scheduled and nothing repeats.
    assert_eq!(sm.next_deadline(), None);
    assert_eq!(sm.handle(Input::Timer, t0), vec![]);

    assert_eq!(sm.handle(Input::Addr(None), t0), vec![]);
    assert_eq!(sm.next_deadline(), Some(t0 + IP_ADDR_WAIT));
    assert_eq!(
        sm.handle(Input::Timer, t0 + IP_ADDR_WAIT),
        vec![Action::ResolveAddr]
    );
    assert_eq!(sm.status().state, FsmState::Init);
}

#[test]
fn solicit_cadence_is_honored() {
    let t0 = Instant::now();
    let mut sm = soliciting(t0);

    assert_eq!(sm.next_deadline(), Some(t0 + SOLICIT_INTERVAL));
    assert_eq!(
        sm.handle(Input::Timer, t0 + SOLICIT_INTERVAL),
        vec![Action::Solicit]
    );
    assert_eq!(sm.next_deadline(), Some(t0 + 2 * SOLICIT_INTERVAL));

    // An early wakeup does not solicit.
    assert_eq!(sm.handle(Input::Timer, t0 + SOLICIT_INTERVAL), vec![]);
    assert_eq!(sm.counters().solicitations_sent, 2);
}

#[test]
fn a_solicitation_draws_an_advertisement() {
    let t0 = Instant::now();
    let mut sm = soliciting(t0);

    let actions = sm.handle(
        Input::Discovery {
            from: peer_addr(),
            packet: Discovery::Solicit,
        },
        t0,
    );
    assert_eq!(actions, vec![Action::Advertise { to: peer_addr() }]);
    assert_eq!(sm.counters().solicitations_received, 1);
    assert_eq!(sm.counters().advertisements_sent, 1);
    // Answering a solicitation does not make the sender our peer.
    assert_eq!(sm.status().peer, None);
}

#[test]
fn exchange_startup_retries_the_bind_then_the_self_pull() {
    let t0 = Instant::now();
    let mut sm = soliciting(t0);

    assert_eq!(
        sm.handle(advertise(peer_addr()), t0),
        vec![Action::StartExchangeServer]
    );
    // The threaded implementation reported Exchange before the bind loop.
    assert_eq!(sm.status().state, FsmState::Exchange);
    let since = sm.status().since;

    let t1 = t0 + Duration::from_millis(10);
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::ExchangeServerStarted(false)), t1),
        vec![]
    );
    assert_eq!(
        sm.next_deadline(),
        Some((t1 + BIND_RETRY).min(t0 + SOLICIT_INTERVAL))
    );

    let t2 = t1 + BIND_RETRY;
    assert_eq!(
        sm.handle(Input::Timer, t2),
        vec![Action::Solicit, Action::StartExchangeServer]
    );
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::ExchangeServerStarted(true)), t2),
        vec![Action::SelfPull]
    );

    assert_eq!(
        sm.handle(Input::Outcome(Outcome::SelfPull(false)), t2),
        vec![]
    );
    assert_eq!(sm.next_deadline(), Some(t2 + READY_POLL));

    let t3 = t2 + READY_POLL;
    assert_eq!(sm.handle(Input::Timer, t3), vec![Action::SelfPull]);
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::SelfPull(true)), t3),
        vec![Action::PeerPull {
            peer: peer_addr(),
            version: Version::V3
        }]
    );

    // Startup is internal: the externally visible state never left Exchange.
    assert_eq!(sm.status().since, since);
}

#[test]
fn the_initial_pull_retries_at_the_solicit_interval() {
    let t0 = Instant::now();
    let mut sm = soliciting(t0);
    sm.handle(advertise(peer_addr()), t0);
    sm.handle(Input::Outcome(Outcome::ExchangeServerStarted(true)), t0);
    sm.handle(Input::Outcome(Outcome::SelfPull(true)), t0);

    assert_eq!(
        sm.handle(Input::Outcome(Outcome::PeerPull(None)), t0),
        vec![]
    );
    assert_eq!(sm.next_deadline(), Some(t0 + SOLICIT_INTERVAL));

    let t1 = t0 + SOLICIT_INTERVAL;
    assert_eq!(
        sm.handle(Input::Timer, t1),
        vec![
            Action::Solicit,
            Action::PeerPull {
                peer: peer_addr(),
                version: Version::V3
            }
        ]
    );

    // Once it lands the retry stops and the response is imported.
    let actions =
        sm.handle(Input::Outcome(Outcome::PeerPull(Some(Box::default()))), t1);
    assert!(matches!(
        actions[..],
        [Action::Rib(RibEvent::Update { .. })]
    ));
    assert_eq!(sm.next_deadline(), Some(t1 + SOLICIT_INTERVAL));
}

#[test]
fn announcements_are_originated_with_our_hostname() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    let actions = sm.handle(
        Input::Admin(AdminEvent::Announce(PrefixSet::Underlay(HashSet::from(
            [net(1)],
        )))),
        t0,
    );
    let [
        Action::SendUpdate {
            peer,
            version,
            update,
        },
    ] = &actions[..]
    else {
        panic!("expected one send, got {actions:?}");
    };
    assert_eq!(*peer, peer_addr());
    assert_eq!(*version, Version::V3);
    let underlay = update.underlay.as_ref().unwrap();
    assert_eq!(
        underlay.announce,
        HashSet::from([v3::PathVector {
            destination: net(1),
            path: vec!["violin".into()],
        }])
    );
    assert!(underlay.withdraw.is_empty());
    assert_eq!(sm.counters().updates_sent, 1);
}

#[test]
fn sends_are_serialized_and_ordered() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    let announce = Input::Admin(AdminEvent::Announce(PrefixSet::Underlay(
        HashSet::from([net(1)]),
    )));
    let withdraw = Input::Admin(AdminEvent::Withdraw(PrefixSet::Underlay(
        HashSet::from([net(1)]),
    )));

    assert_eq!(sm.handle(announce, t0).len(), 1);
    // The second update queues behind the first rather than racing it.
    assert_eq!(sm.handle(withdraw, t0), vec![]);

    let actions = sm.handle(Input::Outcome(Outcome::UpdateSent(true)), t0);
    let [Action::SendUpdate { update, .. }] = &actions[..] else {
        panic!("expected the queued send, got {actions:?}");
    };
    assert!(!update.underlay.as_ref().unwrap().withdraw.is_empty());
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::UpdateSent(true)), t0),
        vec![]
    );
}

#[test]
fn a_failed_send_expires_the_peer_back_to_solicit() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    sm.handle(
        Input::Admin(AdminEvent::Announce(PrefixSet::Underlay(HashSet::from(
            [net(1)],
        )))),
        t0,
    );
    let actions = sm.handle(Input::Outcome(Outcome::UpdateSent(false)), t0);
    assert_eq!(
        actions,
        vec![
            Action::StopExchangeServer,
            Action::Rib(RibEvent::PeerExpired {
                nexthop: peer_addr()
            }),
        ]
    );
    assert_eq!(sm.status().state, FsmState::Solicit);
    assert_eq!(sm.status().peer, None);
    assert_eq!(sm.counters().update_send_fail, 1);
}

#[test]
fn a_silent_neighbor_expires() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    assert_eq!(
        sm.next_deadline(),
        Some((t0 + SOLICIT_INTERVAL).min(t0 + EXPIRE_THRESHOLD))
    );

    // Not yet: the neighbor was heard from inside the threshold.
    let t1 = t0 + EXPIRE_THRESHOLD - Duration::from_millis(1);
    assert_eq!(sm.handle(Input::Timer, t1), vec![Action::Solicit]);
    assert_eq!(sm.status().state, FsmState::Exchange);

    // The threshold is inclusive, because `next_deadline` names exactly this
    // instant and a driver that wakes on it has to make progress.
    let t2 = t0 + EXPIRE_THRESHOLD;
    assert_eq!(sm.next_deadline(), Some(t2));
    assert_eq!(
        sm.handle(Input::Timer, t2),
        vec![
            Action::StopExchangeServer,
            Action::Rib(RibEvent::PeerExpired {
                nexthop: peer_addr()
            }),
        ]
    );
    assert_eq!(sm.status().state, FsmState::Solicit);
    assert_eq!(sm.counters().peer_expirations, 1);

    // With no neighbor there is no expiry deadline, only the solicit cadence.
    assert_eq!(sm.next_deadline(), Some(t1 + SOLICIT_INTERVAL));
}

#[test]
fn a_fresh_advertisement_defers_expiry() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    let t1 = t0 + EXPIRE_THRESHOLD - Duration::from_millis(1);
    sm.handle(advertise(peer_addr()), t1);
    assert_eq!(sm.status().state, FsmState::Exchange);

    let t2 = t0 + EXPIRE_THRESHOLD + Duration::from_millis(1);
    assert!(
        !sm.handle(Input::Timer, t2)
            .iter()
            .any(|a| matches!(a, Action::Rib(RibEvent::PeerExpired { .. })))
    );
    assert_eq!(sm.status().state, FsmState::Exchange);
}

#[test]
fn a_renumbered_peer_is_followed_in_place() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);
    let moved: Ipv6Addr = "fe80::48".parse().unwrap();

    assert_eq!(sm.handle(advertise(moved), t0), vec![]);
    assert_eq!(sm.status().state, FsmState::Exchange);
    assert_eq!(sm.status().peer.unwrap().addr, moved);
    assert_eq!(sm.counters().peer_address_changes, 1);

    let actions = sm.handle(
        Input::Admin(AdminEvent::Announce(PrefixSet::Underlay(HashSet::from(
            [net(1)],
        )))),
        t0,
    );
    let [Action::SendUpdate { peer, .. }] = &actions[..] else {
        panic!("expected a send, got {actions:?}");
    };
    assert_eq!(*peer, moved);
}

#[test]
fn a_failed_solicit_returns_to_init() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    let actions = sm.handle(Input::SolicitFailed, t0);
    assert_eq!(
        actions,
        vec![
            Action::StopExchangeServer,
            Action::Rib(RibEvent::PeerExpired {
                nexthop: peer_addr()
            }),
            Action::CloseSockets,
            Action::ResolveAddr,
        ]
    );
    assert_eq!(sm.status().state, FsmState::Init);
    assert_eq!(sm.status().if_name, "");
}

#[test]
fn an_unknown_protocol_version_is_ignored() {
    let t0 = Instant::now();
    let mut sm = soliciting(t0);

    let actions = sm.handle(
        Input::Discovery {
            from: peer_addr(),
            packet: Discovery::Advertise {
                hostname: "piano".into(),
                kind: RouterKind::Transit,
                version: 9,
            },
        },
        t0,
    );
    assert_eq!(actions, vec![]);
    assert_eq!(sm.status().state, FsmState::Solicit);
    assert_eq!(sm.counters().advertisements_received, 1);
}

#[test]
fn redistribution_forwards_only_the_underlay() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    let update = v3::Update {
        underlay: Some(v3::UnderlayUpdate::announce(HashSet::from([
            v3::PathVector {
                destination: net(2),
                path: vec!["cello".into()],
            },
        ]))),
        tunnel: Some(v3::TunnelUpdate::announce(HashSet::from([
            v3::TunnelOrigin {
                overlay_prefix: "10.0.0.0/24".parse().unwrap(),
                boundary_addr: "fd00:99::1".parse().unwrap(),
                vni: 47,
                metric: 0,
            },
        ]))),
    };

    let actions = sm.handle(Input::Redistribute(Box::new(update)), t0);
    let [Action::SendUpdate { update, .. }] = &actions[..] else {
        panic!("expected one send, got {actions:?}");
    };
    assert!(update.tunnel.is_none());
    assert_eq!(update.underlay.as_ref().unwrap().announce.len(), 1);
}

#[test]
fn admin_events_outside_exchange_are_dropped() {
    let t0 = Instant::now();
    let mut sm = soliciting(t0);

    let actions = sm.handle(
        Input::Admin(AdminEvent::Announce(PrefixSet::Underlay(HashSet::from(
            [net(1)],
        )))),
        t0,
    );
    assert_eq!(actions, vec![]);
}

#[test]
fn a_peer_push_is_handed_to_the_rib() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);
    let before = sm.counters().updates_received;

    let actions = sm.handle(Input::PeerPush(Box::default()), t0);
    let [Action::Rib(RibEvent::Update { peer, ifname, .. })] = &actions[..]
    else {
        panic!("expected one rib event, got {actions:?}");
    };
    assert_eq!(*peer, peer_addr());
    assert_eq!(ifname, "cxgbe0");
    assert_eq!(sm.counters().updates_received, before + 1);
}

#[test]
fn administratively_expiring_the_peer_returns_to_solicit() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    // A different peer is not ours to expire.
    let other: Ipv6Addr = "fe80::99".parse().unwrap();
    assert_eq!(
        sm.handle(Input::Admin(AdminEvent::Expire(other)), t0),
        vec![]
    );
    assert_eq!(sm.status().state, FsmState::Exchange);

    let actions = sm.handle(Input::Admin(AdminEvent::Expire(peer_addr())), t0);
    assert_eq!(
        actions,
        vec![
            Action::StopExchangeServer,
            Action::Rib(RibEvent::PeerExpired {
                nexthop: peer_addr()
            }),
        ]
    );
    assert_eq!(sm.status().state, FsmState::Solicit);
}

#[test]
fn a_sync_pulls_once() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    assert_eq!(
        sm.handle(Input::Admin(AdminEvent::Sync), t0),
        vec![Action::PeerPull {
            peer: peer_addr(),
            version: Version::V3
        }]
    );
    let actions =
        sm.handle(Input::Outcome(Outcome::PeerPull(Some(Box::default()))), t0);
    assert!(matches!(
        actions[..],
        [Action::Rib(RibEvent::Update { .. })]
    ));

    // A failed sync is not retried, unlike the initial pull.
    sm.handle(Input::Admin(AdminEvent::Sync), t0);
    assert_eq!(
        sm.handle(Input::Outcome(Outcome::PeerPull(None)), t0),
        vec![]
    );
    assert_eq!(sm.next_deadline(), Some(t0 + SOLICIT_INTERVAL));
}

#[test]
fn a_stale_outcome_is_ignored() {
    let t0 = Instant::now();
    let mut sm = exchanging(t0);

    sm.handle(
        Input::Admin(AdminEvent::Announce(PrefixSet::Underlay(HashSet::from(
            [net(1)],
        )))),
        t0,
    );
    // The peer expires while the send is in flight.
    sm.handle(Input::Admin(AdminEvent::Expire(peer_addr())), t0);

    assert_eq!(
        sm.handle(Input::Outcome(Outcome::UpdateSent(false)), t0),
        vec![]
    );
    assert_eq!(sm.status().state, FsmState::Solicit);
    assert_eq!(sm.counters().update_send_fail, 0);
}
