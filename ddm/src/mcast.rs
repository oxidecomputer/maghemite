// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Underlay multicast membership programming.
//!
//! Programs the local switch's underlay multicast replication members in the
//! Dendrite (DPD) data plane from the multicast routes DDM has imported from
//! peers. This is the multicast analog of the unicast import-to-DPD path that
//! [`crate::sys::add_underlay_routes`] performs in-process: `ddmd` owns both
//! inputs locally, the imported multicast set ([`Db::imported_mcast`]) and the
//! peer table, so it programs DPD without any cross-daemon coordination.
//!
//! Membership is reconciled by a single periodic sweep over every active
//! underlay group, like the unicast lower-half's resync and `rdb`'s reaper. The
//! control plane never writes multicast members to DPD itself.
//!
//! When a peer's subscription to a group changes, the exchange update handler
//! and peer expiry send the group's address down a notify channel to wake the
//! sweep early. Peer-link resolution does the same for any import that raced
//! ahead of the link. Absent a trigger, the sweep self-ticks on
//! [`RECONCILE_INTERVAL`], which is also the drift-repair backstop. The address
//! on a trigger is only a wake hint: the sweep always reconciles the full set,
//! so a coalesced or missed trigger costs at most one interval of latency.
//!
//! Each sweep recomputes the full, desired member set for every tracked group,
//! repairs any drift, and programs members it could not previously (because the
//! group did not yet exist or a peer link had not resolved). A group whose
//! imports are withdrawn stays in the sweep until its DPD member list is
//! confirmed empty, then drops out, so a withdrawn group is emptied exactly
//! once and the tracked set stays bounded to active and recently active groups.
//!
//! DPD's only member-write surface is a full-list replace, so every member edit
//! is a read-modify-write. Groups reconcile concurrently within a pass, but the
//! sweep is the sole writer and each group is a distinct DPD object, so
//! concurrent edits cannot clobber one another.
//!
//! Each imported [`MulticastRoute`] names the peer (`nexthop`) that advertised
//! a group subscription and that peer is a replication target on this sled.
//! Every next hop is resolved to its switch `(PortId, LinkId)` through the
//! interface the peer was discovered on, and members are aggregated per
//! underlay group.
//!
//! Aggregation keys solely on the underlay group address and discards the
//! overlay group. This is sound because Omicron maps each overlay group to a
//! distinct underlay group, so the mapping is one to one and the underlay
//! address alone identifies a group's replication set. A route's overlay group
//! is carried for diagnostics, not for keying.
//!
//! Omicron owns each underlay group's create and delete. `ddmd` programs only
//! the member set of groups that already exist and authorizes each write
//! against the group's tag, read back from DPD, so it never changes the tag or
//! deletes the group.
//!
//! See [RFD 488] for the multicast architecture.
//!
//! [RFD 488]: https://rfd.shared.oxide.computer/rfd/0488

use crate::db::Db;
use crate::sm::{DpdConfig, SmContext};
use crate::sys::DDM_DPD_TAG;
use ddm_api_types::db::MulticastRoute;
use dpd_client::types::{
    Direction, LinkId, MulticastGroupMember, MulticastGroupUpdateUnderlayEntry,
    MulticastTag, PortId, UnderlayMulticastIpv6,
};
use dpd_client::{Client, ClientState};
use futures::TryStreamExt;
use futures::future::join_all;
use mg_common::lock;
use reqwest::StatusCode;
use slog::{Logger, debug, error, warn};
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

/// Interval between the sweep's periodic membership reconcile passes.
///
/// A trigger wakes the sweep immediately, so this interval governs only the
/// drift-repair backstop: how quickly drift and any change not delivered as a
/// trigger converge into DPD. It is kept coarse to bound idle DPD churn, since
/// membership changes themselves arrive as triggers.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

/// Per-request timeout for a single DPD member operation.
///
/// Bounds one GET or PUT against an unresponsive DPD so a stalled request
/// cannot delay the rest of a sweep pass indefinitely. It is set above the
/// expected DPD member operation latency so that it fires only on a genuine
/// stall, and low enough that a group's sequential fetch-then-write pair
/// (`2 * DPD_REQUEST_TIMEOUT`) stays under [`RECONCILE_INTERVAL`], so a single
/// stalled group cannot extend a pass beyond one backstop interval. This
/// stall-detection threshold is reasoned about independently of the
/// convergence cadence set by [`RECONCILE_INTERVAL`]. A timed-out operation is
/// logged distinctly and retried on the next pass.
const DPD_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Run the multicast membership sweep.
///
/// Loops forever on the calling thread, so callers run it in a dedicated thread.
///
/// Tracks the set of active underlay groups and reconciles them on each pass.
/// `notify_rx` is a wake hint only: a trigger wakes the sweep early, and absent
/// a trigger it self-ticks on [`RECONCILE_INTERVAL`]. Every pass reconciles the
/// full tracked set, so the group address carried by a trigger is not consulted
/// and a coalesced trigger costs at most one interval of latency.
///
/// The tracked set is the union of every currently imported group and any group
/// still being drained. `reconcile_group` returns `false` only once a
/// withdrawn group's DPD members are confirmed empty, so a group leaves the set
/// exactly once its drain is complete. A re-import re-adds it on the next pass
/// since the control plane writes to the DB before sending its trigger.
pub fn run(
    db: Db,
    peers: Vec<SmContext>,
    dpd: DpdConfig,
    rt: Arc<tokio::runtime::Handle>,
    notify_rx: Receiver<Ipv6Addr>,
    log: Logger,
) {
    let client_state = ClientState {
        tag: DDM_DPD_TAG.into(),
        log: log.clone(),
    };
    // Build the inner HTTP client explicitly to bound each request at
    // DPD_REQUEST_TIMEOUT. The progenitor-generated dpd_client defaults to a
    // 15s connect and request timeout, which exceeds RECONCILE_INTERVAL. A
    // single stalled GET could outlast the whole backstop interval, and a
    // sequential fetch-then-write pair could run three times it. Stepping down
    // to DPD_REQUEST_TIMEOUT keeps a stalled group's pair under one interval.
    let http = reqwest::ClientBuilder::new()
        .connect_timeout(DPD_REQUEST_TIMEOUT)
        .timeout(DPD_REQUEST_TIMEOUT)
        .build()
        .expect("failed to build DPD HTTP client");
    let client = Client::new_with_client(
        &format!("http://{}:{}", dpd.host, dpd.port),
        http,
        client_state,
    );

    // On each pass, the sweep reconciles every imported group plus any group
    // still draining withdrawn members, so the set stays bounded to active and
    // recently active groups rather than growing without limit. We seed it from
    // the underlay groups DPD already has members for.
    //
    // On a fresh start, the imported set and triggers only reference groups
    // with live subscriptions, so a group whose imports were withdrawn while
    // `ddmd` was down would never re-enter the sweep and its stale replication
    // members would persist. Folding those groups in once lets the first pass
    // drain any that no peer still imports, while groups still imported simply
    // reconcile as usual.
    let mut tracked: HashSet<Ipv6Addr> = rt
        .block_on(client.member_group_ips(&log))
        .into_iter()
        .collect();

    loop {
        // The imported set and resolved peer links are the same for every group
        // in a pass, so compute them once here rather than per group.
        let imported = db.imported_mcast();
        let peer_links = resolve_peer_links(&peers, &log);

        tracked = rt.block_on(reconcile_pass(
            tracked, imported, peer_links, &client, &log,
        ));

        // Wait for a trigger or the backstop interval, whichever comes first,
        // then drain any burst since the next pass reconciles everything
        // regardless.
        match notify_rx.recv_timeout(RECONCILE_INTERVAL) {
            Ok(_) => while notify_rx.try_recv().is_ok() {},
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                // Unreachable while `ddmd` runs: `main()` owns the original
                // `notify_tx` and parks for the daemon's lifetime, so the
                // channel cannot close even if every per-peer sender clone is
                // torn down. We stop the sweep rather than spin on a closed
                // channel if that invariant ever changes.
                error!(log, "multicast notify channel closed, stopping sweep");
                break;
            }
        }
    }
}

/// Signal the multicast sweep to reconcile each distinct underlay group touched
/// by `routes`.
///
/// The route iterator may repeat a group many times, one entry per next hop.
/// The groups are deduplicated, so the sweep wakes once per affected group. The
/// import and withdraw paths share this so both wake the sweep the same way.
pub(crate) fn notify_affected_groups<'a>(
    routes: impl IntoIterator<Item = &'a MulticastRoute>,
    notify: &Sender<Ipv6Addr>,
) {
    let affected: HashSet<Ipv6Addr> = routes
        .into_iter()
        .map(|route| route.origin.underlay_group.ip())
        .collect();
    notify_groups(affected, notify);
}

/// Wake the multicast sweep once per group in `groups`.
fn notify_groups(groups: HashSet<Ipv6Addr>, notify: &Sender<Ipv6Addr>) {
    for group in groups {
        // Best-effort trigger to wake the multicast sweep. The sweep owns the
        // receiver for the daemon's lifetime, so this send does not fail during
        // normal operation.
        let _ = notify.send(group);
    }
}

/// Wake the multicast sweep for every group `peer` advertised once that peer's
/// link resolves.
///
/// A multicast import already wakes the sweep, but a route imported before the
/// peer link resolved cannot be programmed yet, so it waits out the backstop
/// interval. Waking the peer's groups on resolution closes that window. The
/// imported set is read, not consumed, so this is the non-destructive analog of
/// the [`Db::remove_nexthop_routes`] removal on peer expiry.
pub(crate) fn notify_peer_groups(
    db: &Db,
    peer: Ipv6Addr,
    notify: &Sender<Ipv6Addr>,
) {
    notify_groups(db.mcast_groups_for_nexthop(peer), notify);
}

/// Reconcile every tracked group against DPD once, returning the next tracked
/// set.
///
/// Folds every currently imported group into `tracked`, reconciles the whole
/// set concurrently, and returns only the groups `reconcile_group` reports as
/// still active. A withdrawn group lingers for exactly one pass to empty its DPD
/// members, then drops out on the following pass. Re-importing a dropped group
/// re-adds it here, since Omicron writes to the DB before triggering the sweep.
///
/// The per-group futures run concurrently on this task rather than spawned, so a
/// group whose DPD call stalls does not serialize the others behind it. The pass
/// still returns only once its slowest group completes, but each request is
/// bounded by [`DPD_REQUEST_TIMEOUT`], so a stall delays the pass by that bound
/// at most rather than blocking it indefinitely.
async fn reconcile_pass<C: GroupClient>(
    mut tracked: HashSet<Ipv6Addr>,
    imported: HashSet<MulticastRoute>,
    peer_links: HashMap<Ipv6Addr, (PortId, LinkId)>,
    client: &C,
    log: &Logger,
) -> HashSet<Ipv6Addr> {
    for route in imported.iter() {
        tracked.insert(route.origin.underlay_group.ip());
    }

    // Borrow once so every per-group future shares the same imports and
    // resolved links by reference.
    let imported = &imported;
    let peer_links = &peer_links;
    let reconciled = join_all(tracked.into_iter().map(|group_ip| async move {
        let keep =
            reconcile_group(group_ip, imported, peer_links, client, log).await;
        (group_ip, keep)
    }))
    .await;

    reconciled
        .into_iter()
        .filter_map(|(group_ip, keep)| keep.then_some(group_ip))
        .collect()
}

/// Whether a DPD client error is a request timeout.
///
/// A timeout surfaces as a transport-level error with no HTTP status, so it is
/// distinguished by inspecting the underlying `reqwest::Error` rather than by
/// status code.
fn is_timeout<E>(e: &dpd_client::Error<E>) -> bool {
    matches!(e, dpd_client::Error::CommunicationError(re) if re.is_timeout())
}

/// Outcome of writing a group's member list to DPD.
#[derive(Clone)]
enum WriteOutcome {
    /// Members were written.
    Updated,
    /// DPD no longer authorizes the write against the group's tag.
    ///
    /// The tag, owned by DPD, changed from the value read this pass. On an
    /// active group a later pass reads the current tag and retries. On a
    /// withdrawn group the group was reassigned, so `ddmd` abandons it rather
    /// than retrying.
    TagReassigned,
    /// The group is absent from DPD.
    Gone,
    /// The write stalled past [`DPD_REQUEST_TIMEOUT`].
    ///
    /// Distinguished from [`WriteOutcome::Failed`] so a genuine stall is
    /// surfaced separately, though both retry the group on the next pass.
    TimedOut,
    /// The write failed for an unexpected, non-timeout reason.
    Failed,
}

/// Outcome of reading a group's state from DPD.
#[derive(Clone)]
enum FetchOutcome {
    /// The group exists and its authorization tag and current members were read.
    Found(String, Vec<MulticastGroupMember>),
    /// The group does not exist in DPD, either because Omicron has not created
    /// it yet or because it has been deleted.
    Absent,
    /// The read stalled past [`DPD_REQUEST_TIMEOUT`].
    ///
    /// Distinguished from [`FetchOutcome::ReadFailed`] so a genuine stall is
    /// surfaced separately, though both keep the group tracked for retry.
    TimedOut,
    /// The read failed transiently for a non-timeout reason, so the group's
    /// state is unknown this pass.
    ReadFailed,
}

/// DPD group operations the reconcile loop depends on.
///
/// Abstracted behind a trait so [`reconcile_group`]'s keep/drop logic can be
/// exercised against a mock, without a live DPD endpoint. The production
/// implementation is [`Client`].
trait GroupClient {
    /// Read an underlay group's current members and authorization tag.
    async fn fetch_group(
        &self,
        log: &Logger,
        group_ip: Ipv6Addr,
    ) -> FetchOutcome;

    /// Write `members` to an underlay group, authorized by its current `tag`.
    async fn write_members(
        &self,
        log: &Logger,
        group_ip: Ipv6Addr,
        tag: &str,
        members: Vec<MulticastGroupMember>,
    ) -> WriteOutcome;

    /// Underlay groups that currently have members programmed in DPD.
    ///
    /// Read once at startup to seed the sweep's tracked set. `ddmd` is the sole
    /// writer of underlay members on this switch, so every group returned was
    /// programmed by `ddmd` (or a prior incarnation) and is safe to fold-in. A
    /// failure returns an empty set. Orphan recovery then waits for the next
    /// `ddmd` restart whose listing succeeds, since the periodic sweep
    /// reconciles only tracked and imported groups and never re-lists DPD.
    async fn member_group_ips(&self, log: &Logger) -> Vec<Ipv6Addr>;
}

impl GroupClient for Client {
    /// Distinguishes a group that is genuinely absent (`FetchOutcome::Absent`)
    /// from one whose state could not be read (`FetchOutcome::ReadFailed`), so a
    /// withdrawn group is not dropped from the sweep on a transient read failure
    /// before its members are confirmed drained.
    async fn fetch_group(
        &self,
        log: &Logger,
        group_ip: Ipv6Addr,
    ) -> FetchOutcome {
        let underlay_ip = UnderlayMulticastIpv6::from(group_ip);
        match self.multicast_group_get_underlay(&underlay_ip).await {
            Ok(resp) => {
                let resp = resp.into_inner();
                FetchOutcome::Found(resp.tag, resp.members)
            }
            // The underlay group's create and delete are owned by Omicron, which
            // creates the group before traffic flows. Until the group exists
            // there are no members to program, so skip it.
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {
                debug!(
                    log,
                    "underlay group {group_ip} does not exist yet, skipping \
                     until Omicron creates it"
                );
                FetchOutcome::Absent
            }
            // Surface a stalled read distinctly from other failures. The sweep
            // retries the group on its next pass regardless.
            Err(e) if is_timeout(&e) => {
                warn!(
                    log,
                    "get of underlay group {group_ip} timed out after \
                     {DPD_REQUEST_TIMEOUT:?}, retrying next pass"
                );
                FetchOutcome::TimedOut
            }
            Err(e) => {
                error!(log, "failed to get underlay group {group_ip}: {e}");
                FetchOutcome::ReadFailed
            }
        }
    }

    /// The expected races, a tag change (403) or a deleted group (404), are
    /// returned as outcomes rather than logged, leaving the reaction to the
    /// caller.
    async fn write_members(
        &self,
        log: &Logger,
        group_ip: Ipv6Addr,
        tag: &str,
        members: Vec<MulticastGroupMember>,
    ) -> WriteOutcome {
        let underlay_ip = UnderlayMulticastIpv6::from(group_ip);
        let tag = match MulticastTag::try_from(tag.to_string()) {
            Ok(tag) => tag,
            Err(e) => {
                error!(
                    log,
                    "tag for underlay group {group_ip} is invalid, skipping \
                     update: {e}"
                );
                return WriteOutcome::Failed;
            }
        };
        let body = MulticastGroupUpdateUnderlayEntry { members };
        match self
            .multicast_group_update_underlay(&underlay_ip, &tag, &body)
            .await
        {
            Ok(_) => WriteOutcome::Updated,
            Err(e) if e.status() == Some(StatusCode::FORBIDDEN) => {
                WriteOutcome::TagReassigned
            }
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {
                WriteOutcome::Gone
            }
            // Surface a stalled write distinctly from other failures. Treated as
            // `WriteOutcome::Failed` so the sweep retries it on its next pass.
            Err(e) if is_timeout(&e) => {
                warn!(
                    log,
                    "update of underlay group {group_ip} members timed out \
                     after {DPD_REQUEST_TIMEOUT:?}, retrying next pass"
                );
                WriteOutcome::TimedOut
            }
            Err(e) => {
                error!(
                    log,
                    "failed to update underlay group {group_ip} members: {e}"
                );
                WriteOutcome::Failed
            }
        }
    }

    async fn member_group_ips(&self, log: &Logger) -> Vec<Ipv6Addr> {
        let groups: Vec<dpd_client::types::MulticastGroupResponse> = match self
            .multicast_groups_list_stream(None)
            .try_collect()
            .await
        {
            Ok(groups) => groups,
            Err(e) => {
                warn!(
                    log,
                    "could not list multicast groups to seed sweep, relying \
                         on imports and the periodic backstop: {e}"
                );
                return Vec::new();
            }
        };
        groups
            .into_iter()
            .filter_map(|group| match group {
                dpd_client::types::MulticastGroupResponse::Underlay {
                    group_ip,
                    members,
                    ..
                } if !members.is_empty() => Some(*group_ip),
                _ => None,
            })
            .collect()
    }
}

/// Resolve each established peer's underlay address to a switch
/// `(PortId, LinkId)` through the interface it was discovered on.
///
/// Peers without an established identity, without an interface name, or whose
/// interface does not resolve to a switch link are omitted.
///
/// A peer omitted here is seen by `group_members` as an unresolved next hop, so
/// a transient resolution failure neither drops a previously programmed member
/// nor blocks a newly resolved one.
fn resolve_peer_links(
    peers: &[SmContext],
    log: &Logger,
) -> HashMap<Ipv6Addr, (PortId, LinkId)> {
    let mut peer_links: HashMap<Ipv6Addr, (PortId, LinkId)> = HashMap::new();
    for sm in peers {
        let Some(peer) = lock!(sm.iface.peer_identity).clone() else {
            continue;
        };
        let if_name = lock!(sm.iface.if_name).clone();
        if if_name.is_empty() {
            warn!(
                log,
                "peer {} has no interface name; omitting as multicast member",
                peer.addr
            );
            continue;
        }
        match mg_common::tfport::port_link_from_ifname(&if_name) {
            Ok(port_link) => {
                peer_links.insert(peer.addr, port_link);
            }
            Err(e) => warn!(
                log,
                "cannot resolve peer {} interface {if_name} to a switch link, \
                 omitting as multicast member: {e}",
                peer.addr
            ),
        }
    }
    peer_links
}

/// Aggregate one underlay group's desired replication members.
///
/// Returns the member list for `group_ip` and whether any of its next hops
/// failed to resolve this pass, in which case the derived set may be incomplete.
///
/// Members are derived from each route's `nexthop`. Distinct downstream peers
/// carry distinct next hops, so each becomes its own member. Subscribers reached
/// through the same downstream peer collapse to one member, because a single
/// egress port toward that peer suffices and the next hop handles further
/// fan-out. The path vector is not needed, only the per-node egress set.
fn group_members(
    group_ip: Ipv6Addr,
    imported: &HashSet<MulticastRoute>,
    peer_links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
) -> (Vec<MulticastGroupMember>, bool) {
    let mut members: Vec<MulticastGroupMember> = Vec::new();
    let mut has_unresolved = false;
    for route in imported
        .iter()
        .filter(|route| route.origin.underlay_group.ip() == group_ip)
    {
        let Some((port_id, link_id)) = peer_links.get(&route.nexthop) else {
            has_unresolved = true;
            continue;
        };
        // The single (port, link) here is per next hop, not per group: one peer
        // is reached over one tfport link. A group fans out to as many links as
        // it has distinct downstream peers.
        let member = MulticastGroupMember {
            port_id: port_id.clone(),
            link_id: *link_id,
            direction: Direction::Underlay,
        };
        if !members.contains(&member) {
            members.push(member);
        }
    }
    (members, has_unresolved)
}

/// Reconcile a single underlay group's members in DPD against the multicast
/// routes DDM has imported, returning whether the group is still active.
///
/// The group's current members are read fresh from DPD and diffed against the
/// desired set, so the periodic resync repairs member drift.
///
/// Returns `true` to keep the group tracked, either while it still has imports
/// (as the drift backstop) or whenever its DPD state could not be read this
/// pass, and `false` only once the group has no imports and its DPD member list
/// is confirmed empty, so it drops out of the sweep.
async fn reconcile_group<C: GroupClient>(
    group_ip: Ipv6Addr,
    imported: &HashSet<MulticastRoute>,
    peer_links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
    client: &C,
    log: &Logger,
) -> bool {
    let has_imports = imported
        .iter()
        .any(|route| route.origin.underlay_group.ip() == group_ip);
    let (members, has_unresolved) =
        group_members(group_ip, imported, peer_links);

    let (tag, existing) = match client.fetch_group(log, group_ip).await {
        FetchOutcome::Found(tag, existing) => (tag, existing),
        // The group is absent from DPD, Omicron has not created it or it is
        // deleted. There is nothing to program or drain, so keep it tracked
        // only while it still has imports, so a later pass programs it once it
        // exists.
        FetchOutcome::Absent => return has_imports,
        // The state is unknown at this pass. Keep the group tracked so the next
        // pass retries, whether it is active or still draining withdrawn
        // members. A withdrawn group must not drop out here, or stale
        // replication would stay programmed until some later re-import tracked
        // it again.
        FetchOutcome::TimedOut | FetchOutcome::ReadFailed => return true,
    };

    if !has_imports {
        // Withdrawn: empty the member list to stop replication, leaving the
        // group for Omicron to delete.
        if existing.is_empty() {
            return false;
        }
        return match client.write_members(log, group_ip, &tag, Vec::new()).await
        {
            WriteOutcome::Updated => {
                debug!(
                    log,
                    "emptied withdrawn underlay group {group_ip} members"
                );
                false
            }
            // Already gone, or recreated under a tag that is no longer what
            // we've seen. Either way `ddmd` no longer programs this group.
            WriteOutcome::Gone | WriteOutcome::TagReassigned => false,
            // Retry the empty on the next pass.
            WriteOutcome::TimedOut | WriteOutcome::Failed => true,
        };
    }

    // When a next hop did not resolve this pass, the derived set may be missing
    // members. Merge it with the group's current members so a transient
    // resolution failure neither drops a previously programmed member nor
    // blocks adding a newly resolved one. With every next hop resolved, the
    // derived set replaces the current members.
    let to_write = if has_unresolved {
        let merged = union_members(&members, &existing);
        if merged.len() > members.len() {
            debug!(
                log,
                "underlay group {group_ip} has unresolved next hops, preserving \
                 {} current DPD member(s) beyond the {} derived this pass",
                merged.len() - members.len(),
                members.len()
            );
        }
        merged
    } else {
        members
    };

    if !members_eq(&existing, &to_write) {
        match client.write_members(log, group_ip, &tag, to_write).await {
            WriteOutcome::Updated => {
                debug!(log, "updated underlay group {group_ip} members")
            }
            WriteOutcome::TagReassigned => warn!(
                log,
                "tag no longer authorizes underlay group {group_ip}, retrying \
                 with a fresh read next pass"
            ),
            WriteOutcome::Gone
            | WriteOutcome::Failed
            | WriteOutcome::TimedOut => {}
        }
    }

    // Active group: keep it tracked so the backstop repairs any later drift.
    true
}

/// Union of two multicast member lists, preserving order and dropping
/// duplicates. Used to merge a derived member set with the group's current DPD
/// members when a next hop did not resolve this pass.
fn union_members(
    base: &[MulticastGroupMember],
    extra: &[MulticastGroupMember],
) -> Vec<MulticastGroupMember> {
    base.iter()
        .chain(extra.iter().filter(|member| !base.contains(member)))
        .cloned()
        .collect()
}

/// Compare two multicast member lists for set equality, ignoring order.
fn members_eq(a: &[MulticastGroupMember], b: &[MulticastGroupMember]) -> bool {
    a.len() == b.len() && a.iter().all(|member| b.contains(member))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddm_api_types::net::{MulticastOrigin, UnderlayMulticastIpv6, Vni};
    use std::net::IpAddr;

    fn underlay(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, last)
    }

    fn route(nexthop: Ipv6Addr, group: Ipv6Addr) -> MulticastRoute {
        MulticastRoute {
            origin: MulticastOrigin {
                overlay_group: IpAddr::V6(Ipv6Addr::new(
                    0xff0e, 0, 0, 0, 0, 0, 0, 1,
                )),
                underlay_group: UnderlayMulticastIpv6::new(group).unwrap(),
                vni: Vni::DEFAULT_MULTICAST_VNI,
                metric: 0,
                source: None,
            },
            nexthop,
            path: Vec::new(),
        }
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
    fn distinct_peers_become_distinct_members() {
        let peer_a = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let peer_b = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let group = underlay(1);

        let imported =
            HashSet::from([route(peer_a, group), route(peer_b, group)]);
        let peer_links = HashMap::from([
            (peer_a, rear("rear0", 0)),
            (peer_b, rear("rear1", 0)),
        ]);

        let (members, unresolved) =
            group_members(group, &imported, &peer_links);
        assert!(!unresolved);
        assert_eq!(members.len(), 2);
        assert!(members.contains(&member("rear0", 0)));
        assert!(members.contains(&member("rear1", 0)));
    }

    #[test]
    fn distinct_peers_on_same_link_collapse_to_one_member() {
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

        let (members, unresolved) =
            group_members(group, &imported, &peer_links);
        assert!(!unresolved);
        assert_eq!(members, vec![member("rear0", 0)]);
    }

    #[test]
    fn unresolved_nexthop_yields_no_members_and_sets_flag() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(7);

        let imported = HashSet::from([route(peer, group)]);
        // No peer_links entry: next hop is unresolved.
        let peer_links = HashMap::new();

        let (members, unresolved) =
            group_members(group, &imported, &peer_links);
        assert!(members.is_empty());
        assert!(unresolved);
    }

    #[test]
    fn mixed_resolution_yields_resolved_members_and_sets_flag() {
        let resolved = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let unresolved_peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let group = underlay(3);

        // One next hop resolves and one does not. The resolved peer contributes a
        // member, and the group is still flagged so the reconcile merges with the
        // group's current DPD members rather than dropping the unresolved one.
        let imported = HashSet::from([
            route(resolved, group),
            route(unresolved_peer, group),
        ]);
        let peer_links = HashMap::from([(resolved, rear("rear0", 0))]);

        let (members, unresolved) =
            group_members(group, &imported, &peer_links);
        assert!(unresolved);
        assert_eq!(members, vec![member("rear0", 0)]);
    }

    /// Mock DPD that returns preset fetch and write outcomes, and records every
    /// member list written so a test can assert the reconcile's keep/drop
    /// decision and whether it wrote at all.
    ///
    /// A landed write (`WriteOutcome::Updated`) updates the stored fetch state
    /// to the members just written, so a later fetch reflects it. This models
    /// DPD's read-after-write semantics and lets a multi-pass test observe a
    /// group's drain across passes.
    struct MockDpd {
        fetch: std::sync::Mutex<FetchOutcome>,
        write_outcome: WriteOutcome,
        writes: std::sync::Mutex<Vec<Vec<MulticastGroupMember>>>,
        member_groups: Vec<Ipv6Addr>,
    }

    impl MockDpd {
        fn new(fetch: FetchOutcome, write_outcome: WriteOutcome) -> Self {
            Self {
                fetch: std::sync::Mutex::new(fetch),
                write_outcome,
                writes: std::sync::Mutex::new(Vec::new()),
                member_groups: Vec::new(),
            }
        }

        fn with_member_groups(mut self, groups: Vec<Ipv6Addr>) -> Self {
            self.member_groups = groups;
            self
        }

        fn writes(&self) -> Vec<Vec<MulticastGroupMember>> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl GroupClient for MockDpd {
        async fn fetch_group(
            &self,
            _log: &Logger,
            _group_ip: Ipv6Addr,
        ) -> FetchOutcome {
            self.fetch.lock().unwrap().clone()
        }

        async fn write_members(
            &self,
            _log: &Logger,
            _group_ip: Ipv6Addr,
            tag: &str,
            members: Vec<MulticastGroupMember>,
        ) -> WriteOutcome {
            self.writes.lock().unwrap().push(members.clone());
            if matches!(self.write_outcome, WriteOutcome::Updated) {
                *self.fetch.lock().unwrap() =
                    FetchOutcome::Found(tag.to_string(), members);
            }
            self.write_outcome.clone()
        }

        async fn member_group_ips(&self, _log: &Logger) -> Vec<Ipv6Addr> {
            self.member_groups.clone()
        }
    }

    fn found(members: Vec<MulticastGroupMember>) -> FetchOutcome {
        FetchOutcome::Found("tag".to_string(), members)
    }

    fn reconcile(
        group: Ipv6Addr,
        imported: &HashSet<MulticastRoute>,
        peer_links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
        mock: &MockDpd,
    ) -> bool {
        let log = Logger::root(slog::Discard, slog::o!());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(reconcile_group(group, imported, peer_links, mock, &log))
    }

    fn run_pass(
        tracked: HashSet<Ipv6Addr>,
        imported: &HashSet<MulticastRoute>,
        peer_links: &HashMap<Ipv6Addr, (PortId, LinkId)>,
        mock: &MockDpd,
    ) -> HashSet<Ipv6Addr> {
        let log = Logger::root(slog::Discard, slog::o!());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(reconcile_pass(
            tracked,
            imported.clone(),
            peer_links.clone(),
            mock,
            &log,
        ))
    }

    /// Drives the sweep's cross-pass carry-over invariant: an active group is
    /// tracked, a withdraw lingers one pass to empty its members then drops, and
    /// a re-import re-adds and reprograms it. This exercises the tracked-set
    /// state machine that the run loop builds on.
    #[test]
    fn pass_drains_withdrawn_group_then_drops_and_readds_on_reimport() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let active = HashSet::from([route(peer, group)]);
        let withdrawn = HashSet::new();
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);

        // DPD already holds the derived member, so the group starts active and
        // in sync with the imported set.
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );

        // Pass 1: imported and already in sync, so the group is tracked (no
        // write occurrs).
        let tracked = run_pass(HashSet::new(), &active, &peer_links, &mock);
        assert_eq!(tracked, HashSet::from([group]));
        assert!(mock.writes().is_empty());

        // Pass 2: withdrawn ~ the group carries over from pass 1, its members
        // are emptied, and then it drops out of the tracked set.
        let tracked = run_pass(tracked, &withdrawn, &peer_links, &mock);
        assert!(tracked.is_empty());
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);

        // Pass 3: re-imported ~ the dropped group is re-added and reprogrammed,
        // since DPD now holds no members for it.
        let tracked = run_pass(tracked, &active, &peer_links, &mock);
        assert_eq!(tracked, HashSet::from([group]));
        assert_eq!(mock.writes(), vec![Vec::new(), vec![member("rear0", 0)]]);
    }

    /// A group whose imports were withdrawn while `ddmd` was down has no entry
    /// in the imported set or any trigger, so only the startup seed can
    /// re-initialize it.
    #[test]
    fn startup_seeds_tracked_from_dpd_and_drains_orphans() {
        let group = underlay(9);
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        )
        .with_member_groups(vec![group]);
        let log = Logger::root(slog::Discard, slog::o!());
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let seeded: HashSet<Ipv6Addr> = rt
            .block_on(mock.member_group_ips(&log))
            .into_iter()
            .collect();
        assert!(seeded.contains(&group));

        let next = run_pass(seeded, &HashSet::new(), &HashMap::new(), &mock);
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
        assert!(next.is_empty());
    }

    #[test]
    fn absent_group_with_imports_stays_tracked() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(FetchOutcome::Absent, WriteOutcome::Updated);

        // Omicron has not created the group yet, so there is nothing to program,
        // but it stays tracked so a later pass programs it once it exists.
        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn absent_group_without_imports_drops() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock = MockDpd::new(FetchOutcome::Absent, WriteOutcome::Updated);

        assert!(!reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn withdrawn_group_with_read_failure_stays_tracked() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock =
            MockDpd::new(FetchOutcome::ReadFailed, WriteOutcome::Updated);

        // A withdrawn group must not drop out on a transient read failure, or
        // its stale replication would stay programmed until a later re-import.
        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn withdrawn_group_with_read_timeout_stays_tracked() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock = MockDpd::new(FetchOutcome::TimedOut, WriteOutcome::Updated);

        // A read stall is treated like any other transient read failure: the
        // withdrawn group stays tracked so a later pass can drain it.
        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn withdrawn_group_with_no_members_drops_without_writing() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::Updated);

        assert!(!reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn withdrawn_group_with_members_is_emptied_then_drops() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );

        assert!(!reconcile(group, &imported, &peer_links, &mock));
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
    }

    #[test]
    fn withdrawn_group_with_empty_write_failure_stays_tracked() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock =
            MockDpd::new(found(vec![member("rear0", 0)]), WriteOutcome::Failed);

        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
    }

    #[test]
    fn withdrawn_group_with_empty_write_timeout_stays_tracked() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::TimedOut,
        );

        // The empty write stalled, so the group stays tracked to retry the
        // drain on the next pass.
        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
    }

    #[test]
    fn withdrawn_group_with_tag_reassigned_on_empty_drops() {
        let group = underlay(1);
        let imported = HashSet::new();
        let peer_links = HashMap::new();
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::TagReassigned,
        );

        // The group was reassigned under a tag we no longer hold, so `ddmd`
        // abandons it rather than retrying.
        //
        // This is distinct from the active-group case, where a reassigned tag
        // stays tracked for a fresh read.
        assert!(!reconcile(group, &imported, &peer_links, &mock));
        assert_eq!(mock.writes(), vec![Vec::<MulticastGroupMember>::new()]);
    }

    #[test]
    fn active_group_with_matching_members_skips_write() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );

        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn active_group_with_drifted_members_writes_derived_set() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::Updated);

        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert_eq!(mock.writes(), vec![vec![member("rear0", 0)]]);
    }

    #[test]
    fn active_group_with_unresolved_nexthop_preserves_existing_member() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        // No peer_links entry: the next hop is unresolved this pass.
        let peer_links = HashMap::new();
        let mock = MockDpd::new(
            found(vec![member("rear0", 0)]),
            WriteOutcome::Updated,
        );

        // The derived set is empty because the next hop did not resolve, but
        // the merge with current DPD members keeps the programmed member, so no
        // destructive write occurs.
        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert!(mock.writes().is_empty());
    }

    #[test]
    fn active_group_with_tag_reassigned_stays_tracked() {
        let peer = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let group = underlay(1);
        let imported = HashSet::from([route(peer, group)]);
        let peer_links = HashMap::from([(peer, rear("rear0", 0))]);
        let mock = MockDpd::new(found(Vec::new()), WriteOutcome::TagReassigned);

        // The write was rejected because the tag changed, but the group is
        // still active, so it stays tracked to retry with a fresh read next
        // pass.
        assert!(reconcile(group, &imported, &peer_links, &mock));
        assert_eq!(mock.writes(), vec![vec![member("rear0", 0)]]);
    }

    #[test]
    fn notify_collapses_routes_to_one_trigger_per_group() {
        let group_a = underlay(1);
        let group_b = underlay(2);
        let peer_a = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let peer_b = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

        // Two next hops on group_a and one on group_b. The sweep should wake
        // once per distinct group, not once per route.
        let routes = [
            route(peer_a, group_a),
            route(peer_b, group_a),
            route(peer_a, group_b),
        ];

        let (tx, rx) = std::sync::mpsc::channel();
        notify_affected_groups(routes.iter(), &tx);
        drop(tx);

        let signalled: Vec<Ipv6Addr> = rx.into_iter().collect();
        assert_eq!(signalled.len(), 2);
        assert_eq!(
            signalled.into_iter().collect::<HashSet<_>>(),
            HashSet::from([group_a, group_b])
        );
    }
}
