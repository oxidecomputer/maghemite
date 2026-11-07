// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Underlay multicast membership programming.
//!
//! Programs multicast routes DDM has imported from peers into the local
//! switch's underlay multicast replication member set operated by the
//! Dendrite (DPD) dataplane. This is the multicast analog of
//! unicast's import-to-DPD setup which `add_underlay_routes` performs
//! in-process. With `ddmd` owning its input locally, i.e., the imported
//! multicast set along with the interface each route's peer was discovered
//! on ([`imported_mcast_links`]), it programs DPD directly.
//!
//! ## Membership Reconciliation
//!
//! Membership reconciliation runs by way of a periodic sweep over all active
//! underlay groups, similar to how the unicast lower-half's resync works. When
//! updates are made to the imported multicast set, whether from the exchange
//! update handler, peer expiry, or protocol downgrade, they all operate through
//! [`Db`], which wakes the sweep mechanism early (see
//! [`Db::subscribe_mcast_sweep`]). Otherwise, the sweep waits out
//! `RECONCILE_INTERVAL` after each pass before starting the next one.
//!
//! On each pass, we recompute the wanted member set for every group containing
//! imports or programmed members (withdrawn groups included), then repair
//! drift, drain withdrawn groups, and program members we could not
//! previously resolve (e.g., the group hadn't existed yet or an interface had
//! not resolved to a switch link).
//!
//! The sweep removes only members recorded as programmed since this `ddmd`
//! process started up, akin to ddmd's handling of unicast and tunnel routes.
//! A matching read or a successful write records the members derived from
//! imports, including those already in DPD. A failed write retains the prior
//! record and adds the wanted members because DPD may have already applied it.
//! Programmed members are removed when no import can derive them, and a group
//! stays in the sweep until it has no imports or programmed members.
//!
//! A member no import has derived since this process started, such as one left
//! by an earlier `ddmd` process, remains in place.
//!
//! DPD replaces the full member set on each write. Unicast and tunnel updates
//! can add or remove entries without reading back the full set. However, inline
//! multicast updates would need serialization per group along with a retry
//! mechanism. The sweep provides both: a single task reconciling groups one at
//! a time, and subsequent passes retrying failures. Each pass consolidates
//! route updates into at most one read-modify-write per group, avoiding
//! unnecessary writes when the computed member set matches DPD.
//!
//! ## DPD Groups and Membership
//!
//! Each imported [`MulticastRoute`] identifies an advertising peer (`nexthop`),
//! and is kept with the interface that peer was discovered on, akin to how
//! unicast routes work. This interface supplies the switch `(PortId, LinkId)`
//! tuple entry, while resolved members are deduplicated per underlay group
//! address (which is DPD's group key); the overlay group is not part of this
//! key.
//!
//! Nexus creates each underlay group and deletes it by tag. Within an existing
//! group, `ddmd` writes the members whose packet copies keep their Geneve
//! encapsulation (`Underlay` in DPD) and preserves the members whose copies
//! are decapsulated before delivery (`External`).
//! Rack-originated traffic already carries Geneve encapsulation addressed to
//! the underlay group and bypasses ingress NAT ([DPD packet paths]).
//!
//! Writes pass back the tag from the same pass's read, which the
//! [DPD update API] checks against the group's tag. So `ddmd` only ever
//! replaces the member list (never the tag, never the group itself).
//!
//! See [RFD 488] for the multicast architecture.
//!
//! [RFD 488]: https://rfd.shared.oxide.computer/rfd/0488
//! [`imported_mcast_links`]: crate::db::Db::imported_mcast_links
//! [DPD packet paths]: https://github.com/oxidecomputer/dendrite/blob/3019e6f0c73ded56be5c36cbaca82dbbc796a346/dpd/src/mcast/mod.rs#L22-L25
//! [DPD update API]: https://github.com/oxidecomputer/dendrite/blob/3019e6f0c73ded56be5c36cbaca82dbbc796a346/dpd-api/src/lib.rs#L2496-L2512

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use ddm_api_types::db::MulticastRoute;
use ddm_api_types::net::UnderlayMulticastIpv6;
use dpd_client::types::{
    Direction, MulticastGroupMember, MulticastGroupUnderlayResponse,
    MulticastGroupUpdateUnderlayEntry, PortId,
};
use dpd_client::{Client, ClientState};
use dpd_types_versions::latest::mcast::MulticastTag;
use hyper::StatusCode;
use slog::{Logger, debug, error, info, warn};
use tokio::sync::watch;

use crate::DDM_TAG;
use crate::db::Db;
use crate::sm::DpdConfig;

/// The interval between the sweep's periodic membership reconciliation passes.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

/// Run the multicast membership reconciliation sweep until it's explicitly
/// canceled.
///
/// This reconciles imported and draining groups on wakes from
/// [`Db::subscribe_mcast_sweep`] or via periodic ticks. Switch links are
/// resolved on each pass from the interface each route's peer was discovered
/// on, including dynamically added external peers.
///
/// Each new `ddmd` process starts without a record of programmed membership,
/// which means that existing members it never derives again could remain
/// in DPD indefinitely.
///
/// TODO: Recover forwarding state after restart across multicast, unicast,
/// and tunnel routes. We retain existing behavior here: [unicast and
/// tunnel cleanup] also uses only the current imported set.
///
/// TODO: Count sweep outcomes (passes, writes, failures, missing groups) in
/// [`RouterStats`] once the `ddm-router.toml` schema can export them.
///
/// [`RouterStats`]: crate::admin::RouterStats
/// [unicast and tunnel cleanup]: https://github.com/oxidecomputer/maghemite/blob/04a64f5b6b80dadbfa6ece123a30304b2f82414e/ddm/src/sm/state.rs#L357-L378
pub async fn run(db: Db, dpd: DpdConfig, log: Logger) {
    let mcast = db.subscribe_mcast_sweep();
    let client = Client::new(
        &format!("http://{}:{}", dpd.host, dpd.port),
        ClientState {
            tag: DDM_TAG.into(),
            log: log.clone(),
        },
    );
    run_with_client(db, &client, mcast, log).await;
}

async fn run_with_client<C: GroupClient>(
    db: Db,
    client: &C,
    mut mcast: watch::Receiver<u64>,
    log: Logger,
) {
    let mut programmed: ProgrammedMembers = HashMap::new();
    let mut unresolved = HashSet::new();

    loop {
        // Before reading the imported set, we mark the current generation
        // number as seen. If an update advances the generation during this
        // pass, another pass starts without waiting for the timer.
        mcast.borrow_and_update();

        // For each group within a pass, the imported set is the same snapshot,
        // which means we can read it once here, avoiding a per-group lookup.
        let imported = db.imported_mcast_links();

        reconcile_pass(
            &mut programmed,
            &mut unresolved,
            &imported,
            client,
            &log,
        )
        .await;

        // Wait for a wake cycle or one idle reconcile interval.
        //
        // Both waits (below) are cancel-safe.
        //
        // If an update races with selection of the sleep branch, the next
        // pass will mark it seen and read the set that includes it.
        tokio::select! {
            Ok(()) = mcast.changed() => {}
            _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
        }
    }
}

/// The per-group `Underlay` members programmed since this sweep started.
type ProgrammedMembers = HashMap<UnderlayMulticastIpv6, Members>;
type Members = HashSet<MulticastGroupMember>;

/// Reconcile active groups with imports or programmed members.
///
/// An empty result drops the group's entry, recorded nothing for it.
/// A group that still contains imports (e.g., a group Nexus has not yet
/// created) is picked back up on the next pass via those imports.
async fn reconcile_pass<C: GroupClient>(
    programmed: &mut ProgrammedMembers,
    unresolved: &mut HashSet<String>,
    imported: &[(MulticastRoute, String)],
    client: &C,
    log: &Logger,
) {
    let mut by_group: HashMap<UnderlayMulticastIpv6, Vec<&str>> =
        HashMap::new();
    for (route, ifname) in imported {
        by_group
            .entry(route.origin.underlay_group())
            .or_default()
            .push(ifname);
    }
    let groups: BTreeSet<UnderlayMulticastIpv6> =
        by_group.keys().chain(programmed.keys()).copied().collect();
    let links = resolve_links(
        imported.iter().map(|(_, ifname)| ifname.as_str()),
        unresolved,
        log,
    );

    for group_ip in groups {
        let ifnames = by_group.get(&group_ip).map_or(&[][..], Vec::as_slice);
        let prev = programmed.remove(&group_ip).unwrap_or_default();
        let members = reconcile_group(
            group_ip,
            ifnames.iter().copied(),
            &links,
            prev,
            client,
            log,
        )
        .await;

        if !members.is_empty() {
            programmed.insert(group_ip, members);
        }
    }
}

/// The outcome of writing a group's member list to DPD.
#[derive(Clone, Copy)]
enum WriteOutcome {
    /// Members were written.
    Updated,
    /// The write failed and should be retried on the next pass.
    Retry,
}

/// The outcome of reading a group's state from DPD.
#[derive(Clone)]
enum FetchOutcome {
    /// The fetched group exists, and its authorization tag and current members
    /// were read without issue.
    Found(MulticastTag, Vec<MulticastGroupMember>),
    /// The fetched group does not exist in DPD, maybe because Nexus has not
    /// created it yet or because it was deleted before this operation.
    Missing,
    /// The read operation failed, making the group's state unknown on this
    /// pass, for which a retry should ensue.
    Retry,
}

/// Behavior encompassing DPD group operations that the reconciliation relies
/// on.
///
/// NOTE: tests implement this trait in order to inject failures and pause
/// requests.
trait GroupClient {
    /// Read an underlay group's current members along with its authorization
    /// tag.
    async fn fetch_group(
        &self,
        log: &Logger,
        group_ip: UnderlayMulticastIpv6,
    ) -> FetchOutcome;

    /// Write `members` to an underlay group, authorized by its current `tag`.
    async fn write_members(
        &self,
        log: &Logger,
        group_ip: UnderlayMulticastIpv6,
        tag: &MulticastTag,
        members: Vec<MulticastGroupMember>,
    ) -> WriteOutcome;
}

impl GroupClient for Client {
    /// This distinguishes a group that is genuinely missing
    /// (`FetchOutcome::Missing`) from one with state that could not be read
    /// (`FetchOutcome::Retry`) at the time of execution.
    ///
    /// Therefore, a withdrawn group is not dropped from the sweep when
    /// encountering a transient read failure before its members are confirmed
    /// drained.
    async fn fetch_group(
        &self,
        log: &Logger,
        group_ip: UnderlayMulticastIpv6,
    ) -> FetchOutcome {
        match self.multicast_group_get_underlay(&group_ip).await {
            Ok(resp) => {
                let MulticastGroupUnderlayResponse { tag, members, .. } =
                    resp.into_inner();
                MulticastTag::try_from(tag)
                    .map(|tag| FetchOutcome::Found(tag, members))
                    .unwrap_or_else(|e| {
                        error!(
                            log,
                            "tag for underlay group {group_ip} is invalid, \
                             retrying next pass: {e}"
                        );
                        FetchOutcome::Retry
                    })
            }
            // The creation and deletion of an underlay group is owned by Nexus,
            // which creates the group before traffic flows toward it.
            //
            // We bypass membership programming until the group exists.
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {
                debug!(
                    log,
                    "underlay group {group_ip} does not exist yet, bypassing \
                     until Nexus creates it"
                );
                FetchOutcome::Missing
            }
            Err(e) => {
                warn!(log, "failed to get underlay group {group_ip}: {e}");
                FetchOutcome::Retry
            }
        }
    }

    /// Any failure, including a 404 or a 400 for a retag since the read, is
    /// [`WriteOutcome::Retry`]. DPD also returns 404 for a missing ASIC
    /// resource on a group that still exists, so the next pass's read decides
    /// whether the group is gone.
    async fn write_members(
        &self,
        log: &Logger,
        group_ip: UnderlayMulticastIpv6,
        tag: &MulticastTag,
        members: Vec<MulticastGroupMember>,
    ) -> WriteOutcome {
        let body = MulticastGroupUpdateUnderlayEntry { members };
        match self
            .multicast_group_update_underlay(&group_ip, tag, &body)
            .await
        {
            Ok(_) => WriteOutcome::Updated,
            Err(dpd_client::Error::ErrorResponse(resp))
                if resp.error_code.as_deref()
                    == Some(dpd_client::MCAST_TAG_MISMATCH_ERROR_CODE) =>
            {
                debug!(
                    log,
                    "underlay group {group_ip} tag changed since the read, \
                     retrying next pass"
                );
                WriteOutcome::Retry
            }
            Err(e) => {
                warn!(
                    log,
                    "failed to update underlay group {group_ip} members: {e}"
                );
                WriteOutcome::Retry
            }
        }
    }
}

/// Aggregate one underlay group's wanted replication members.
///
/// `ifnames` are the interfaces on which the peers behind an underlay group's
/// imports were discovered.
/// Interfaces that don't resolve to a switch link during this pass do not
/// contribute toward membership.
///
/// Members are derived from each import's interface. All distinct downstream
/// links convey distinct interfaces, making each of these its own member.
/// Subscribers reached through a duplicate downstream link collapse into one
/// member because a single egress port toward that peer is sufficient enough
/// and the next set of hop handlers all fan-out further.
fn group_members<'a>(
    ifnames: impl IntoIterator<Item = &'a str>,
    links: &HashMap<&str, MulticastGroupMember>,
) -> Members {
    ifnames
        .into_iter()
        .filter_map(|ifname| links.get(ifname).cloned())
        .collect()
}

/// Resolve each distinct interface in `imported` to an `Underlay` member once
/// per pass.
///
/// Interfaces that cannot resolve to a switch link, or that resolve to a
/// non-rear port, are not retained.
fn resolve_links<'a>(
    imported: impl IntoIterator<Item = &'a str>,
    unresolved: &mut HashSet<String>,
    log: &Logger,
) -> HashMap<&'a str, MulticastGroupMember> {
    let ifnames: BTreeSet<&str> = imported.into_iter().collect();
    unresolved.retain(|ifname| ifnames.contains(ifname.as_str()));

    ifnames
        .into_iter()
        .filter_map(|ifname| {
            let (port_id, link_id) =
                mg_common::tfport::port_link_from_untagged_ifname(ifname)
                    .inspect_err(|e| {
                        if !unresolved.contains(ifname) {
                            unresolved.insert(ifname.to_string());
                            warn!(
                                log,
                                "cannot resolve interface {ifname} to a \
                                 switch link, omitting as multicast \
                                 member: {e}"
                            )
                        }
                    })
                    .ok()?;

            // TODO: Allow QSFP members once inter-rack replication has loop
            // prevention (e.g., RPF or a designated forwarder).
            if !matches!(port_id, PortId::Rear(_)) {
                if !unresolved.contains(ifname) {
                    unresolved.insert(ifname.to_string());
                    debug!(
                        log,
                        "skipping multicast member on {ifname} ({port_id}), \
                         cross-rack replication is not supported"
                    );
                }
                return None;
            }
            unresolved.remove(ifname);
            Some((
                ifname,
                MulticastGroupMember {
                    port_id,
                    link_id,
                    direction: Direction::Underlay,
                },
            ))
        })
        .collect()
}

/// Reconcile an underlay group's members in DPD against the imported multicast
/// routes DDM contains, returning the members to record as programmed.
///
/// With wanted members `D`, existing DPD members `E`, and previously
/// programmed members `P`, the write consists of `D ∪ (E \ P)`.
///
/// Existing members outside of `P` are preserved, including those left over
/// from an earlier run. When no longer wanted, members in `P` are removed.
///
/// # Notes
///
/// - A matching read or a successful write records `D`, including any existing
///   member it must now account for.
/// - A failed read preserves `P`, as the next pass may need to remove
///   members no longer wanted.
/// - A failed write records `P ∪ D`, as DPD may have already applied the
///   operation.
/// - A missing group records nothing whatsoever.
async fn reconcile_group<'a, C: GroupClient>(
    group_ip: UnderlayMulticastIpv6,
    ifnames: impl IntoIterator<Item = &'a str>,
    links: &HashMap<&str, MulticastGroupMember>,
    programmed: Members,
    client: &C,
    log: &Logger,
) -> Members {
    let wanted = group_members(ifnames, links);

    let (tag, existing) = match client.fetch_group(log, group_ip).await {
        FetchOutcome::Found(tag, existing) => {
            (tag, existing.into_iter().collect::<Members>())
        }
        // The group is missing from DPD -> Nexus has not created it or it has
        // been deleted, holding 0 members.
        //
        // We keep the group while it still has imports, giving way for a later
        // pass to program it once it exists.
        FetchOutcome::Missing => return Members::new(),
        // The read state is unknown at this point.
        //
        // We keep the programmed members around for the next pass to remove
        // what was programmed.
        FetchOutcome::Retry => return programmed,
    };

    let mut to_write = &existing - &programmed;
    to_write.extend(wanted.iter().cloned());
    if to_write == existing {
        return wanted;
    }

    let members = to_write.into_iter().collect();
    match client.write_members(log, group_ip, &tag, members).await {
        WriteOutcome::Updated => {
            info!(log, "updated underlay group {group_ip} members");
            wanted
        }
        WriteOutcome::Retry => &programmed | &wanted,
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ddm_api_types::net::{MulticastOrigin, OverlayMulticast, Vni};
    use dpd_client::types::LinkId;
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response};
    use hyper_util::rt::TokioIo;
    use slog::Drain;
    use tokio::net::TcpListener;
    use tokio::sync::{Notify, oneshot};

    use super::*;

    fn underlay(last: u16) -> UnderlayMulticastIpv6 {
        UnderlayMulticastIpv6::new(Ipv6Addr::new(
            0xff04, 0, 0, 0, 0, 0, 0, last,
        ))
        .unwrap()
    }

    fn route(
        nexthop: Ipv6Addr,
        group: UnderlayMulticastIpv6,
    ) -> MulticastRoute {
        MulticastRoute {
            origin: MulticastOrigin::new(
                OverlayMulticast::new(IpAddr::V6(Ipv6Addr::new(
                    0xff0e, 0, 0, 0, 0, 0, 0, 1,
                )))
                .unwrap(),
                group,
                Vni::new(77).unwrap(),
                None,
            )
            .unwrap(),
            nexthop,
            path: Vec::new(),
        }
    }

    fn learned(
        imported: &HashSet<MulticastRoute>,
        links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
    ) -> Vec<(MulticastRoute, String)> {
        imported
            .iter()
            .map(|route| {
                let ifname = links.get(&route.nexthop).map_or_else(
                    || "vioif0".to_string(),
                    |(port_id, link_id)| {
                        format!("tfport{port_id}_{}", link_id.0)
                    },
                );
                (route.clone(), ifname)
            })
            .collect()
    }

    fn group_ifnames(
        group: UnderlayMulticastIpv6,
        learned: &[(MulticastRoute, String)],
    ) -> impl Iterator<Item = &str> {
        learned
            .iter()
            .filter(move |(route, _)| route.origin.underlay_group() == group)
            .map(|(_, ifname)| ifname.as_str())
    }

    fn resolved_members(
        group: UnderlayMulticastIpv6,
        imported: &HashSet<MulticastRoute>,
        links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
    ) -> Members {
        let learned = learned(imported, links);
        let log = Logger::root(slog::Discard, slog::o!());
        group_members(
            group_ifnames(group, &learned),
            &resolve_links(
                learned.iter().map(|(_, ifname)| ifname.as_str()),
                &mut HashSet::new(),
                &log,
            ),
        )
    }

    fn rear(port: &str, link: u8) -> (PortId, LinkId) {
        (
            PortId::Rear(dpd_client::types::Rear::try_from(port).unwrap()),
            LinkId(link),
        )
    }

    fn member(port: &str, link: u8) -> MulticastGroupMember {
        let (port_id, link_id) = rear(port, link);
        MulticastGroupMember {
            port_id,
            link_id,
            direction: Direction::Underlay,
        }
    }

    #[test]
    fn unresolved_interfaces_warn_once_until_removed() {
        let warnings = Arc::new(AtomicUsize::new(0));
        let skips = Arc::new(AtomicUsize::new(0));
        let (warned, skipped) = (warnings.clone(), skips.clone());
        let drain = slog::Filter::new(slog::Discard, move |record| {
            match record.level() {
                slog::Level::Warning => warned.fetch_add(1, Ordering::Relaxed),
                slog::Level::Debug => skipped.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
            true
        });
        let log = Logger::root(drain.ignore_res(), slog::o!());
        let mut unresolved = HashSet::new();

        let links = resolve_links(
            ["vioif0", "vioif0", "bad0", "tfportqsfp0_0", "tfportrear0_0"],
            &mut unresolved,
            &log,
        );
        assert_eq!(
            links,
            HashMap::from([("tfportrear0_0", member("rear0", 0))]),
        );
        assert_eq!(warnings.load(Ordering::Relaxed), 2);
        assert_eq!(skips.load(Ordering::Relaxed), 1);
        assert_eq!(
            unresolved,
            HashSet::from([
                "vioif0".to_string(),
                "bad0".to_string(),
                "tfportqsfp0_0".to_string(),
            ]),
        );

        resolve_links(
            ["vioif0", "bad0", "tfportqsfp0_0", "tfportrear0_0"],
            &mut unresolved,
            &log,
        );
        assert_eq!(warnings.load(Ordering::Relaxed), 2);
        assert_eq!(skips.load(Ordering::Relaxed), 1);

        resolve_links(["bad0"], &mut unresolved, &log);
        assert_eq!(unresolved, HashSet::from(["bad0".to_string()]));
        assert_eq!(warnings.load(Ordering::Relaxed), 2);

        resolve_links(
            ["vioif0", "bad0", "tfportqsfp0_0"],
            &mut unresolved,
            &log,
        );
        assert_eq!(warnings.load(Ordering::Relaxed), 3);
        assert_eq!(skips.load(Ordering::Relaxed), 2);

        resolve_links([], &mut unresolved, &log);
        assert!(unresolved.is_empty());
    }

    #[test]
    fn membership_follows_links() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let both = vec![
            (route(peer, group), "tfportrear0_0".to_string()),
            (route(peer, group), "tfportrear1_0".to_string()),
        ];
        let one = vec![(route(peer, group), "tfportrear1_0".to_string())];
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::Updated);
        let log = Logger::root(slog::Discard, slog::o!());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let mut programmed = HashMap::new();
        let mut unresolved = HashSet::new();
        rt.block_on(reconcile_pass(
            &mut programmed,
            &mut unresolved,
            &both,
            &mock,
            &log,
        ));
        assert_eq!(
            programmed,
            HashMap::from([(
                group,
                set(&[member("rear0", 0), member("rear1", 0)])
            )])
        );

        rt.block_on(reconcile_pass(
            &mut programmed,
            &mut unresolved,
            &one,
            &mock,
            &log,
        ));
        assert_eq!(
            programmed,
            HashMap::from([(group, set(&[member("rear1", 0)]))])
        );
        let writes = mock.writes();
        assert_eq!(writes.len(), 2);
        assert_eq!(
            set(&writes[0]),
            set(&[member("rear0", 0), member("rear1", 0)])
        );
        assert_eq!(writes[1], vec![member("rear1", 0)]);
    }

    #[test]
    fn same_link_peers_share_membership() {
        let peer_a = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let peer_b = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let group = underlay(1);

        // Two distinct peers that resolve to the same switch link. Replicating
        // twice out one (PortId, LinkId) would duplicate delivery on that link,
        // so the members collapse to one. The dedup keys on the resolved link,
        // not on the next hop.
        let imported =
            HashSet::from([route(peer_a, group), route(peer_b, group)]);
        let peer_links = HashMap::from([
            (peer_a, rear("rear0", 0)),
            (peer_b, rear("rear0", 0)),
        ]);

        let members = resolved_members(group, &imported, &peer_links);
        assert_eq!(members, set(&[member("rear0", 0)]));
    }

    #[test]
    fn unresolved_interfaces_are_skipped() {
        let resolved = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let unresolved_peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let group = underlay(3);

        let imported = HashSet::from([
            route(resolved, group),
            route(unresolved_peer, group),
        ]);
        let peer_links = HashMap::from([(resolved, rear("rear0", 0))]);

        let members = resolved_members(group, &imported, &peer_links);
        assert_eq!(members, set(&[member("rear0", 0)]));
    }

    /// The sender signals that a fetch started, and the receiver waits for the
    /// test to resume it.
    type FetchChannels = (oneshot::Sender<()>, oneshot::Receiver<()>);

    /// Records write operations and makes successful updates visible to
    /// fetches.
    struct MockDpd {
        fetch: std::sync::Mutex<FetchOutcome>,
        fetch_by_group:
            std::sync::Mutex<HashMap<UnderlayMulticastIpv6, FetchOutcome>>,
        write_outcome: WriteOutcome,
        writes: std::sync::Mutex<
            Vec<(UnderlayMulticastIpv6, Vec<MulticastGroupMember>)>,
        >,
        fetch_channels: std::sync::Mutex<Option<FetchChannels>>,
        fetch_result_tx:
            std::sync::Mutex<Option<oneshot::Sender<FetchOutcome>>>,
        write_attempted: Notify,
    }

    impl MockDpd {
        fn new(fetch: FetchOutcome, write_outcome: WriteOutcome) -> Self {
            Self {
                fetch: std::sync::Mutex::new(fetch),
                fetch_by_group: std::sync::Mutex::new(HashMap::new()),
                write_outcome,
                writes: std::sync::Mutex::new(Vec::new()),
                fetch_channels: std::sync::Mutex::new(None),
                fetch_result_tx: std::sync::Mutex::new(None),
                write_attempted: Notify::new(),
            }
        }

        fn writes(&self) -> Vec<Vec<MulticastGroupMember>> {
            self.group_writes()
                .into_iter()
                .map(|(_, members)| members)
                .collect()
        }

        fn group_writes(
            &self,
        ) -> Vec<(UnderlayMulticastIpv6, Vec<MulticastGroupMember>)> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl GroupClient for MockDpd {
        async fn fetch_group(
            &self,
            _log: &Logger,
            group_ip: UnderlayMulticastIpv6,
        ) -> FetchOutcome {
            let channels = self.fetch_channels.lock().unwrap().take();
            if let Some((started, resume)) = channels {
                started.send(()).unwrap();
                resume.await.unwrap();
            }
            let outcome =
                self.fetch_by_group.lock().unwrap().get(&group_ip).cloned();
            let outcome =
                outcome.unwrap_or_else(|| self.fetch.lock().unwrap().clone());
            if let Some(tx) = self.fetch_result_tx.lock().unwrap().take() {
                assert!(tx.send(outcome.clone()).is_ok());
            }
            outcome
        }

        async fn write_members(
            &self,
            _log: &Logger,
            group_ip: UnderlayMulticastIpv6,
            tag: &MulticastTag,
            members: Vec<MulticastGroupMember>,
        ) -> WriteOutcome {
            self.writes
                .lock()
                .unwrap()
                .push((group_ip, members.clone()));

            if matches!(self.write_outcome, WriteOutcome::Updated) {
                let updated = FetchOutcome::Found(tag.clone(), members);
                let overridden = {
                    let mut by_group = self.fetch_by_group.lock().unwrap();
                    match by_group.get_mut(&group_ip) {
                        Some(outcome) => {
                            *outcome = updated.clone();
                            true
                        }
                        None => false,
                    }
                };
                if !overridden {
                    *self.fetch.lock().unwrap() = updated;
                }
            }
            self.write_attempted.notify_one();
            self.write_outcome
        }
    }

    fn found(members: Vec<MulticastGroupMember>) -> FetchOutcome {
        FetchOutcome::Found(MulticastTag::try_from("tag").unwrap(), members)
    }

    fn reconcile(
        group: UnderlayMulticastIpv6,
        imported: &HashSet<MulticastRoute>,
        peer_links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
        programmed: Members,
        mock: &MockDpd,
    ) -> Members {
        let log = Logger::root(slog::Discard, slog::o!());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let learned = learned(imported, peer_links);

        rt.block_on(reconcile_group(
            group,
            group_ifnames(group, &learned),
            &resolve_links(
                learned.iter().map(|(_, ifname)| ifname.as_str()),
                &mut HashSet::new(),
                &log,
            ),
            programmed,
            mock,
            &log,
        ))
    }

    fn run_sweep(
        mut programmed: ProgrammedMembers,
        imported: &HashSet<MulticastRoute>,
        peer_links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
        mock: &MockDpd,
    ) -> ProgrammedMembers {
        let log = Logger::root(slog::Discard, slog::o!());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        rt.block_on(reconcile_pass(
            &mut programmed,
            &mut HashSet::new(),
            &learned(imported, peer_links),
            mock,
            &log,
        ));
        programmed
    }

    fn set(members: &[MulticastGroupMember]) -> Members {
        members.iter().cloned().collect()
    }

    #[tokio::test(start_paused = true)]
    async fn mid_sweep_change_wakes_next_sweep() {
        let dir = camino_tempfile::Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log.clone()).unwrap();
        let peer = "fe80::1".parse().unwrap();
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        db.splice_imported_mcast(crate::db::MulticastRibChange::new(
            "tfportrear0_0",
            &imported,
            &HashSet::new(),
        ));

        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );
        let (started_tx, started_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        *mock.fetch_channels.lock().unwrap() = Some((started_tx, resume_rx));

        let sweep =
            run_with_client(db.clone(), &mock, db.subscribe_mcast_sweep(), log);
        let check = async {
            tokio::time::timeout(RECONCILE_INTERVAL / 2, started_rx)
                .await
                .expect("first sweep did not reach the DPD fetch")
                .unwrap();
            db.remove_nexthop_mcast_routes(peer, "tfportrear0_0");
            resume_tx.send(()).unwrap();

            tokio::time::timeout(
                RECONCILE_INTERVAL / 2,
                mock.write_attempted.notified(),
            )
            .await
            .expect("withdrawal during sweep did not wake the next sweep");
            assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
        };
        tokio::select! {
            _ = sweep => panic!("sweep exited"),
            _ = check => {}
        }
    }

    #[test]
    fn group_drains_and_returns_across_sweeps() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let active = HashSet::from([route(peer, group)]);
        let withdrawn = HashSet::new();
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );

        // Sweep 1: imported and already in sync, the sweep counts the
        // existing member as having been programmed (without an explicit
        // write).
        let programmed = run_sweep(HashMap::new(), &active, &peer_links, &mock);
        assert_eq!(
            programmed,
            HashMap::from([(group, set(&[member("rear0", 0)]))])
        );
        assert!(mock.writes().is_empty());

        // Sweep 2: the withdrawn group carries over from sweep 1, its
        // programmed member is removed, and then it drops out of the sweep.
        let programmed = run_sweep(programmed, &withdrawn, &peer_links, &mock);
        assert!(programmed.is_empty());
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);

        // Sweep 3: the dropped group is re-imported and reconfigured (the group
        // contains no membership in DPD).
        let programmed = run_sweep(programmed, &active, &peer_links, &mock);
        assert_eq!(
            programmed,
            HashMap::from([(group, set(&[member("rear0", 0)]))])
        );
        assert_eq!(mock.writes(), vec![Vec::new(), vec![member("rear0", 0)]]);
    }

    /// Case: after a restart, the sweep acts as a no-op for members it has not
    /// yet programmed.
    ///
    /// - A leftover member by the previous `ddmd` process is not removed, akin
    ///   to stale unicast routes.
    /// - A leftover member that an import re-derives is counted as programmed
    ///   and is removed once that import is finally withdrawn.
    #[test]
    fn a_restart_keeps_leftover_members() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear1", 0))]);
        let mock = MockDpd::new(
            found(vec![member("rear0", 0), member("rear1", 0)]),
            WriteOutcome::Updated,
        );

        let programmed =
            run_sweep(HashMap::new(), &imported, &peer_links, &mock);
        assert_eq!(
            programmed,
            HashMap::from([(group, set(&[member("rear1", 0)]))])
        );
        assert!(mock.writes().is_empty());

        let programmed =
            run_sweep(programmed, &HashSet::new(), &peer_links, &mock);
        assert!(programmed.is_empty());
        assert_eq!(mock.writes(), vec![vec![member("rear0", 0)]]);
    }

    #[test]
    fn existing_members_are_kept_on_addition() {
        let peer = "fe80::1".parse().unwrap();
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(
            found(vec![member("rear1", 0), external("qsfp0", 0)]),
            WriteOutcome::Updated,
        );

        let programmed =
            reconcile(group, &imported, &peer_links, Members::new(), &mock);
        assert_eq!(programmed, set(&[member("rear0", 0)]));
        let writes = mock.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            set(&writes[0]),
            set(&[
                member("rear0", 0),
                member("rear1", 0),
                external("qsfp0", 0)
            ])
        );

        let programmed =
            reconcile(group, &imported, &peer_links, programmed.clone(), &mock);
        assert_eq!(programmed, set(&[member("rear0", 0)]));
        assert_eq!(mock.writes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_group_is_retried_on_periodic_sweep() {
        let dir = camino_tempfile::Utf8TempDir::new().unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let db = Db::new(dir.path().as_str(), log.clone()).unwrap();
        let peer = "fe80::1".parse().unwrap();
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        db.splice_imported_mcast(crate::db::MulticastRibChange::new(
            "tfportrear0_0",
            &imported,
            &HashSet::new(),
        ));
        let imports = db.imported_mcast_links();
        let wakes = db.subscribe_mcast_sweep();

        let mock = MockDpd::new(FetchOutcome::Missing, WriteOutcome::Updated);
        let (fetched_tx, fetched_rx) = oneshot::channel();
        *mock.fetch_result_tx.lock().unwrap() = Some(fetched_tx);
        let sweep =
            run_with_client(db.clone(), &mock, db.subscribe_mcast_sweep(), log);
        let check = async {
            let result =
                tokio::time::timeout(RECONCILE_INTERVAL / 2, fetched_rx)
                    .await
                    .expect("first sweep did not fetch the missing group")
                    .unwrap();
            assert!(matches!(result, FetchOutcome::Missing));
            assert!(mock.writes().is_empty());

            let missing_at = tokio::time::Instant::now();
            *mock.fetch.lock().unwrap() = found(Vec::new());
            tokio::time::timeout(
                RECONCILE_INTERVAL * 2,
                mock.write_attempted.notified(),
            )
            .await
            .expect("periodic sweep did not program the newly created group");

            assert!(missing_at.elapsed() >= RECONCILE_INTERVAL);
            assert_eq!(mock.writes(), vec![vec![member("rear0", 0)]]);
            assert_eq!(db.imported_mcast_links(), imports);
            assert!(!wakes.has_changed().unwrap());
        };
        tokio::select! {
            _ = sweep => panic!("sweep exited"),
            _ = check => {}
        }
    }

    #[test]
    fn deleted_group_drops() {
        let group = underlay(1);
        let mock = MockDpd::new(FetchOutcome::Missing, WriteOutcome::Updated);

        assert_eq!(
            reconcile(
                group,
                &HashSet::new(),
                &HashMap::new(),
                set(&[member("rear0", 0)]),
                &mock,
            ),
            Members::new()
        );
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn read_retry_keeps_withdrawn_group() {
        let group = underlay(1);
        let mock = MockDpd::new(FetchOutcome::Retry, WriteOutcome::Updated);

        // A withdrawn group must not drop out on a transient read failure, or
        // its programmed members would stay with nothing to remove them.
        assert_eq!(
            reconcile(
                group,
                &HashSet::new(),
                &HashMap::new(),
                set(&[member("rear0", 0)]),
                &mock,
            ),
            set(&[member("rear0", 0)])
        );
        assert!(mock.writes().is_empty());
    }

    #[tokio::test]
    async fn transport_failure_retries_withdrawal() {
        read_failure_retries_withdrawal(None).await;
    }

    #[tokio::test]
    async fn http_503_retries_withdrawal() {
        read_failure_retries_withdrawal(Some(StatusCode::SERVICE_UNAVAILABLE))
            .await;
    }

    async fn read_failure_retries_withdrawal(
        failure_status: Option<StatusCode>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let log = Logger::root(slog::Discard, slog::o!());
        let client = Client::new(
            &format!("http://{}", listener.local_addr().unwrap()),
            ClientState {
                tag: DDM_TAG.into(),
                log: log.clone(),
            },
        );
        let group = underlay(1);
        let rear0 = member("rear0", 0);
        let preserved = external("qsfp0", 0);
        let members =
            std::sync::Mutex::new(vec![rear0.clone(), preserved.clone()]);
        let unavailable = AtomicBool::new(false);
        let failures = AtomicUsize::new(0);
        let writes = AtomicUsize::new(0);

        let server = async {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                if failure_status.is_none()
                    && unavailable.load(Ordering::Relaxed)
                {
                    failures.fetch_add(1, Ordering::Relaxed);
                    drop(socket);
                    continue;
                }

                let service = service_fn(|request: Request<Incoming>| {
                    let members = &members;
                    let writes = &writes;
                    let unavailable = &unavailable;
                    let failures = &failures;
                    async move {
                        assert_eq!(
                            request.uri().path(),
                            format!("/multicast/underlay-groups/{group}")
                        );
                        if let Some(status) = failure_status
                            .filter(|_| unavailable.load(Ordering::Relaxed))
                        {
                            assert_eq!(request.method(), Method::GET);
                            failures.fetch_add(1, Ordering::Relaxed);
                            let body = serde_json::json!({
                                "message": "multicast group repair failed",
                                "request_id": "test",
                            });
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(
                                        body.to_string(),
                                    )))
                                    .unwrap(),
                            );
                        }
                        if request.method() == Method::PUT {
                            assert_eq!(request.uri().query(), Some("tag=tag"));
                            let body = request
                                .into_body()
                                .collect()
                                .await
                                .unwrap()
                                .to_bytes();
                            let update: MulticastGroupUpdateUnderlayEntry =
                                serde_json::from_slice(&body).unwrap();
                            *members.lock().unwrap() = update.members;
                            writes.fetch_add(1, Ordering::Relaxed);
                        } else {
                            assert_eq!(request.method(), Method::GET);
                        }
                        let body = serde_json::to_vec(
                            &MulticastGroupUnderlayResponse {
                                group_ip: group,
                                tag: "tag".into(),
                                external_group_id: 100,
                                underlay_group_id: 101,
                                members: members.lock().unwrap().clone(),
                            },
                        )
                        .unwrap();
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(socket), service)
                    .await
                    .unwrap();
            }
        };
        let check = async {
            let peer = "fe80::1".parse().unwrap();
            let imported =
                vec![(route(peer, group), "tfportrear0_0".to_string())];
            let mut programmed = HashMap::new();
            let mut unresolved = HashSet::new();

            reconcile_pass(
                &mut programmed,
                &mut unresolved,
                &imported,
                &client,
                &log,
            )
            .await;
            assert_eq!(
                programmed,
                HashMap::from([(group, set(&[member("rear0", 0)]))])
            );
            assert_eq!(writes.load(Ordering::Relaxed), 0);

            unavailable.store(true, Ordering::Relaxed);
            reconcile_pass(
                &mut programmed,
                &mut unresolved,
                &[],
                &client,
                &log,
            )
            .await;
            assert!(failures.load(Ordering::Relaxed) > 0);
            assert_eq!(
                programmed,
                HashMap::from([(group, set(&[member("rear0", 0)]))])
            );
            assert_eq!(
                set(&members.lock().unwrap()),
                set(&[rear0, preserved.clone()])
            );
            assert_eq!(writes.load(Ordering::Relaxed), 0);

            unavailable.store(false, Ordering::Relaxed);
            reconcile_pass(
                &mut programmed,
                &mut unresolved,
                &[],
                &client,
                &log,
            )
            .await;
            assert!(programmed.is_empty());
            assert_eq!(set(&members.lock().unwrap()), set(&[preserved]));
            assert_eq!(writes.load(Ordering::Relaxed), 1);
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                _ = server => panic!("test DPD server exited"),
                _ = check => {}
            }
        })
        .await
        .expect("withdrawal did not recover after the read failure");
    }

    #[test]
    fn withdrawn_group_with_no_members_drops_without_writing() {
        let group = underlay(1);
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::Updated);

        assert_eq!(
            reconcile(
                group,
                &HashSet::new(),
                &HashMap::new(),
                set(&[member("rear0", 0)]),
                &mock,
            ),
            Members::new()
        );
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn empty_write_retry_keeps_withdrawn_group() {
        let group = underlay(1);
        let mock =
            MockDpd::new(found(vec![member("rear0", 0)]), WriteOutcome::Retry);

        assert_eq!(
            reconcile(
                group,
                &HashSet::new(),
                &HashMap::new(),
                set(&[member("rear0", 0)]),
                &mock,
            ),
            set(&[member("rear0", 0)])
        );
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
    }

    #[test]
    fn write_retry_retains_member_for_later_withdrawal() {
        let peer = "fe80::1".parse().unwrap();
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mut mock = MockDpd::new(found(Vec::new()), WriteOutcome::Retry);

        let programmed =
            reconcile(group, &imported, &peer_links, Members::new(), &mock);

        *mock.fetch.lock().unwrap() = found(vec![member("rear0", 0)]);
        mock.write_outcome = WriteOutcome::Updated;

        assert_eq!(
            reconcile(
                group,
                &HashSet::new(),
                &peer_links,
                programmed.clone(),
                &mock
            ),
            Members::new()
        );
        assert_eq!(mock.writes(), vec![vec![member("rear0", 0)], Vec::new()]);
    }

    #[test]
    fn active_group_with_drifted_members_writes_wanted_set() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::Updated);

        assert_eq!(
            reconcile(
                group,
                &imported,
                &peer_links,
                set(&[member("rear0", 0)]),
                &mock
            ),
            set(&[member("rear0", 0)])
        );
        assert_eq!(mock.writes(), vec![vec![member("rear0", 0)]]);
    }

    /// A programmed member whose interface no longer resolves to a switch link
    /// is removed, which would occur on peer expiration.
    #[test]
    fn unresolved_interface_removes_programmed_member() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );

        assert_eq!(
            reconcile(
                group,
                &imported,
                &HashMap::new(),
                set(&[member("rear0", 0)]),
                &mock,
            ),
            Members::new()
        );
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
    }

    #[test]
    fn only_programmed_members_are_removed() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(
            found(vec![
                member("rear0", 0),
                member("rear1", 0),
                member("rear2", 0),
                external("qsfp0", 0),
            ]),
            WriteOutcome::Updated,
        );

        assert_eq!(
            reconcile(
                group,
                &imported,
                &peer_links,
                set(&[member("rear0", 0), member("rear1", 0)]),
                &mock,
            ),
            set(&[member("rear0", 0)])
        );
        let writes = mock.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            set(&writes[0]),
            set(&[
                member("rear0", 0),
                member("rear2", 0),
                external("qsfp0", 0)
            ])
        );
    }

    fn external(port: &str, link: u8) -> MulticastGroupMember {
        MulticastGroupMember {
            port_id: PortId::Qsfp(
                dpd_client::types::Qsfp::try_from(port).unwrap(),
            ),
            link_id: LinkId(link),
            direction: Direction::External,
        }
    }

    #[test]
    fn drain_keeps_external_members() {
        let group = underlay(1);
        let mock = MockDpd::new(
            found(vec![member("rear0", 0), external("qsfp0", 0)]),
            WriteOutcome::Updated,
        );

        assert_eq!(
            reconcile(
                group,
                &HashSet::new(),
                &HashMap::new(),
                set(&[member("rear0", 0)]),
                &mock,
            ),
            Members::new()
        );
        assert_eq!(mock.writes(), vec![vec![external("qsfp0", 0)]]);
    }

    #[test]
    fn group_outcomes_are_independent() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let readable_peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let retried = underlay(1);
        let missing = underlay(2);
        let readable = underlay(3);
        let imported = HashSet::from([
            route(peer, retried),
            route(peer, missing),
            route(readable_peer, readable),
        ]);
        let peer_links = HashMap::from([
            (peer, rear("rear0", 0)),
            (readable_peer, rear("rear2", 0)),
        ]);
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::Updated);
        mock.fetch_by_group.lock().unwrap().extend([
            (retried, FetchOutcome::Retry),
            (missing, FetchOutcome::Missing),
            (readable, found(vec![member("rear1", 0)])),
        ]);

        let prev = HashMap::from([
            (retried, set(&[member("rear1", 0)])),
            (missing, set(&[member("rear1", 0)])),
        ]);
        let programmed = run_sweep(prev, &imported, &peer_links, &mock);
        assert_eq!(
            programmed,
            HashMap::from([
                (retried, set(&[member("rear1", 0)])),
                (readable, set(&[member("rear2", 0)])),
            ])
        );
        let writes = mock.group_writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, readable);
        assert_eq!(
            set(&writes[0].1),
            set(&[member("rear1", 0), member("rear2", 0)])
        );
    }
}
