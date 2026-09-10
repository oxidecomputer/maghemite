// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use ddm_protocol_types::v3::{PathVector, TunnelOrigin, UnderlayUpdate};
use oxnet::Ipv6Net;
use pretty_assertions::assert_eq;

const IFNAME: &str = "cxgbe0";

fn peer(n: u16) -> Ipv6Addr {
    format!("fe80::{n}").parse().unwrap()
}

fn net(n: u16) -> Ipv6Net {
    format!("fd00:{n}::/64").parse().unwrap()
}

fn pv(n: u16, path: &[&str]) -> PathVector {
    PathVector {
        destination: net(n),
        path: path.iter().map(|s| s.to_string()).collect(),
    }
}

fn announce(from: Ipv6Addr, prefixes: Vec<PathVector>) -> RibEvent {
    RibEvent::Update {
        peer: from,
        ifname: IFNAME.to_owned(),
        update: Box::new(
            UnderlayUpdate::announce(prefixes.into_iter().collect()).into(),
        ),
    }
}

fn withdraw(from: Ipv6Addr, prefixes: Vec<PathVector>) -> RibEvent {
    RibEvent::Update {
        peer: from,
        ifname: IFNAME.to_owned(),
        update: Box::new(
            UnderlayUpdate::withdraw(prefixes.into_iter().collect()).into(),
        ),
    }
}

fn tunnel_announce(from: Ipv6Addr, n: u16, metric: u64) -> RibEvent {
    RibEvent::Update {
        peer: from,
        ifname: IFNAME.to_owned(),
        update: Box::new(
            v3::TunnelUpdate::announce([tunnel_origin(n, metric)].into())
                .into(),
        ),
    }
}

fn tunnel_origin(n: u16, metric: u64) -> TunnelOrigin {
    TunnelOrigin {
        overlay_prefix: "0.0.0.0/0".parse().unwrap(),
        boundary_addr: format!("fd00:b{n}::1").parse().unwrap(),
        vni: 99,
        metric,
    }
}

fn server() -> Rib {
    Rib::new("s1".to_owned(), RouterKind::Server)
}

fn transit() -> Rib {
    Rib::new("t1".to_owned(), RouterKind::Transit)
}

fn vectors(out: &[Route]) -> Vec<(Ipv6Net, Ipv6Addr)> {
    let mut v: Vec<_> =
        out.iter().map(|r| (r.destination, r.nexthop)).collect();
    v.sort();
    v
}

#[test]
fn announce_adds_route_and_imports_it() {
    let mut rib = server();
    let out = rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

    assert_eq!(vectors(&out.add_underlay), vec![(net(1), peer(1))]);
    assert!(out.del_underlay.is_empty());
    assert_eq!(rib.imported().len(), 1);
}

#[test]
fn server_router_never_redistributes() {
    let mut rib = server();
    let out = rib.apply(announce(peer(1), vec![pv(1, &["a"])]));
    assert!(out.redistribute.is_none());
}

#[test]
fn transit_router_appends_itself_to_the_path() {
    let mut rib = transit();
    let out = rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

    let underlay = out.redistribute.unwrap().underlay.unwrap();
    let paths: Vec<Vec<String>> =
        underlay.announce.iter().map(|x| x.path.clone()).collect();
    assert_eq!(paths, vec![vec!["a".to_owned(), "t1".to_owned()]]);
}

/// The rule this whole core exists to make testable: many paths can share one
/// (destination, nexthop) vector, and the forwarding platform only knows the
/// vector. Withdrawing one path must not delete the route.
#[test]
fn withdraw_of_one_path_leaves_the_vector_programmed() {
    let mut rib = server();
    rib.apply(announce(peer(1), vec![pv(1, &["a"]), pv(1, &["b"])]));

    let out = rib.apply(withdraw(peer(1), vec![pv(1, &["a"])]));

    assert!(
        out.del_underlay.is_empty(),
        "route deleted while path b still carries the vector"
    );
    assert_eq!(rib.imported().len(), 1);
}

#[test]
fn withdraw_of_the_last_path_deletes_the_vector() {
    let mut rib = server();
    rib.apply(announce(peer(1), vec![pv(1, &["a"]), pv(1, &["b"])]));
    rib.apply(withdraw(peer(1), vec![pv(1, &["a"])]));

    let out = rib.apply(withdraw(peer(1), vec![pv(1, &["b"])]));

    assert_eq!(vectors(&out.del_underlay), vec![(net(1), peer(1))]);
    assert!(rib.imported().is_empty());
}

/// The same destination via two different peers is two vectors. Losing one
/// must not disturb the other.
#[test]
fn withdraw_is_scoped_to_the_nexthop() {
    let mut rib = server();
    rib.apply(announce(peer(1), vec![pv(1, &["a"])]));
    rib.apply(announce(peer(2), vec![pv(1, &["a"])]));

    let out = rib.apply(withdraw(peer(1), vec![pv(1, &["a"])]));

    assert_eq!(vectors(&out.del_underlay), vec![(net(1), peer(1))]);
    assert_eq!(rib.imported().len(), 1);
}

#[test]
fn withdrawing_an_unknown_path_deletes_nothing() {
    let mut rib = server();
    rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

    let out = rib.apply(withdraw(peer(1), vec![pv(2, &["z"])]));

    assert_eq!(vectors(&out.del_underlay), vec![(net(2), peer(1))]);
    assert_eq!(rib.imported().len(), 1);
}

#[test]
fn expiry_drops_every_route_learned_through_the_peer() {
    let mut rib = server();
    rib.apply(announce(peer(1), vec![pv(1, &["a"]), pv(2, &["a"])]));
    rib.apply(announce(peer(2), vec![pv(3, &["a"])]));

    let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(1) });

    assert_eq!(
        vectors(&out.del_underlay),
        vec![(net(1), peer(1)), (net(2), peer(1))]
    );
    assert_eq!(rib.imported().len(), 1);
}

#[test]
fn transit_redistributes_withdraws_on_expiry() {
    let mut rib = transit();
    rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

    let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(1) });

    let underlay = out.redistribute.unwrap().underlay.unwrap();
    assert!(underlay.announce.is_empty());
    let paths: Vec<Vec<String>> =
        underlay.withdraw.iter().map(|x| x.path.clone()).collect();
    assert_eq!(paths, vec![vec!["a".to_owned(), "t1".to_owned()]]);
}

#[test]
fn expiring_an_unknown_peer_is_a_no_op() {
    let mut rib = transit();
    rib.apply(announce(peer(1), vec![pv(1, &["a"])]));

    let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(9) });

    assert!(out.del_underlay.is_empty());
    assert!(out.del_tunnel.is_empty());
    let redistribute = out.redistribute.unwrap();
    assert!(redistribute.underlay.is_none());
    assert!(redistribute.tunnel.is_none());
}

#[test]
fn tunnel_announce_programs_the_endpoint() {
    let mut rib = server();
    let out = rib.apply(tunnel_announce(peer(1), 1, 0));

    assert_eq!(out.add_tunnel.len(), 1);
    assert!(out.del_tunnel.is_empty());
}

/// A nonzero metric makes the whole overlay prefix prefer the metric-bearing
/// origins, so an announce can *delete* a previously programmed endpoint.
#[test]
fn a_higher_metric_evicts_the_zero_metric_endpoints() {
    let mut rib = server();
    rib.apply(tunnel_announce(peer(1), 1, 0));

    let out = rib.apply(tunnel_announce(peer(2), 2, 100));

    assert_eq!(out.add_tunnel.len(), 1);
    assert_eq!(out.del_tunnel.len(), 1);
    let deleted = out.del_tunnel.iter().next().unwrap();
    assert_eq!(deleted.nexthop, peer(1));
}

#[test]
fn expiry_drops_tunnel_endpoints_too() {
    let mut rib = server();
    rib.apply(tunnel_announce(peer(1), 1, 0));

    let out = rib.apply(RibEvent::PeerExpired { nexthop: peer(1) });

    assert_eq!(out.del_tunnel.len(), 1);
    assert!(rib.imported_tunnel().is_empty());
}
