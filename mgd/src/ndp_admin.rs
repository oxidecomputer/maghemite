// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Admin endpoints for the NDP/unnumbered router-discovery subsystem.

use crate::admin::HandlerContext;
use crate::unnumbered_manager::{NdpPeerState, NdpThreadStateInternal};
use chrono::{DateTime, SecondsFormat, Utc};
use dropshot::{HttpError, HttpResponseOk, Query, RequestContext};
use mg_api_types::bgp::config::AsnSelector;
use mg_api_types::ndp::{
    NdpInterface, NdpInterfaceSelector, NdpManagerState, NdpPeer,
    NdpPendingInterface, NdpThreadState,
};
use mg_api_types_versions::v5;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Convert an Instant to an ISO 8601 timestamp string
fn instant_to_iso8601(when: Instant) -> String {
    let now_instant = Instant::now();
    let now_system = SystemTime::now();
    let elapsed = now_instant.duration_since(when);
    let system_time = now_system - elapsed;
    DateTime::<Utc>::from(system_time)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Convert NdpPeerState to API type with timestamp formatting
fn convert_ndp_peer_to_api(state: &NdpPeerState) -> NdpPeer {
    let elapsed_since_when = Instant::now().duration_since(state.when);

    // Format timestamps: first_seen for when peer was discovered,
    // when for when the most recent RA was received
    let discovered_at = instant_to_iso8601(state.first_seen);
    let last_advertisement = instant_to_iso8601(state.when);

    // Calculate time until expiry
    let effective_lifetime =
        Duration::from_secs(u64::from(state.router_lifetime));
    let time_until_expiry = if state.expired {
        // Calculate time since expiry
        let time_since_expiry = elapsed_since_when
            .checked_sub(effective_lifetime)
            .unwrap_or(Duration::ZERO);
        Some(mg_common::format_duration_human(time_since_expiry))
    } else {
        // Calculate time until expiry
        let time_until = effective_lifetime
            .checked_sub(elapsed_since_when)
            .unwrap_or(Duration::ZERO);
        Some(mg_common::format_duration_human(time_until))
    };

    NdpPeer {
        address: state.address,
        discovered_at,
        last_advertisement,
        router_lifetime: state.router_lifetime,
        reachable_time: state.reachable_time,
        retrans_timer: state.retrans_timer,
        expired: state.expired,
        time_until_expiry,
    }
}

/// Convert internal thread state to API type
fn convert_thread_state_to_api(
    state: Option<&NdpThreadStateInternal>,
) -> Option<NdpThreadState> {
    state.map(|s| NdpThreadState {
        tx_running: s.tx_running,
        rx_running: s.rx_running,
    })
}

pub async fn get_ndp_manager_state(
    rqctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<NdpManagerState>, HttpError> {
    let ctx = rqctx.context();

    // Get manager state from unnumbered manager
    let manager_state = ctx.bgp.unnumbered_manager.get_manager_state();

    // Convert pending interfaces to API type
    let pending_interfaces = manager_state
        .pending_interfaces
        .into_iter()
        .map(|p| NdpPendingInterface {
            interface: p.interface,
            router_lifetime: p.router_lifetime,
        })
        .collect();

    Ok(HttpResponseOk(NdpManagerState {
        monitor_thread_running: manager_state.monitor_thread_running,
        pending_interfaces,
        active_interfaces: manager_state.active_interfaces,
    }))
}

fn build_ndp_interfaces(
    ctx: &HandlerContext,
    neighbors: Vec<mg_api_types::rdb::neighbor::BgpUnnumberedNeighborInfo>,
) -> Vec<NdpInterface> {
    let ndp_state = ctx.bgp.unnumbered_manager.list_ndp_interfaces();
    let mut result = Vec::new();
    for neighbor in neighbors {
        if let Some(ndp) = ndp_state
            .iter()
            .find(|info| info.interface == neighbor.interface)
        {
            result.push(NdpInterface {
                interface: neighbor.interface.clone(),
                local_address: ndp.local_address,
                scope_id: ndp.scope_id,
                router_lifetime: neighbor.router_lifetime,
                discovered_peer: ndp
                    .peer_state
                    .as_ref()
                    .map(convert_ndp_peer_to_api),
                thread_state: convert_thread_state_to_api(
                    ndp.thread_state.as_ref(),
                ),
            });
        }
    }
    result
}

pub async fn get_ndp_interfaces(
    rqctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<NdpInterface>>, HttpError> {
    let ctx = rqctx.context();
    let unnumbered_neighbors =
        ctx.db.get_unnumbered_bgp_neighbors().map_err(|e| {
            HttpError::for_internal_error(format!(
                "failed to get unnumbered neighbors: {e}"
            ))
        })?;
    Ok(HttpResponseOk(build_ndp_interfaces(
        ctx,
        unnumbered_neighbors,
    )))
}

pub async fn get_ndp_interfaces_v5(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<NdpInterface>>, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();

    // Prior form: scope the interface list to the requested ASN.
    let unnumbered_neighbors = ctx
        .db
        .get_unnumbered_bgp_neighbors()
        .map_err(|e| {
            HttpError::for_internal_error(format!(
                "failed to get unnumbered neighbors: {e}"
            ))
        })?
        .into_iter()
        .filter(|n| n.asn == rq.asn)
        .collect::<Vec<_>>();

    Ok(HttpResponseOk(build_ndp_interfaces(
        ctx,
        unnumbered_neighbors,
    )))
}

fn ndp_interface_detail(
    ctx: &HandlerContext,
    neighbor: &mg_api_types::rdb::neighbor::BgpUnnumberedNeighborInfo,
) -> Result<HttpResponseOk<NdpInterface>, HttpError> {
    let ndp_detail = ctx
        .bgp
        .unnumbered_manager
        .get_ndp_interface_detail(&neighbor.interface)
        .map_err(|e| {
            HttpError::for_internal_error(format!(
                "failed to get NDP state: {e}"
            ))
        })?
        .ok_or_else(|| {
            HttpError::for_not_found(
                None,
                format!("interface {} not managed by NDP", neighbor.interface),
            )
        })?;

    Ok(HttpResponseOk(NdpInterface {
        interface: neighbor.interface.clone(),
        local_address: ndp_detail.local_address,
        scope_id: ndp_detail.scope_id,
        router_lifetime: neighbor.router_lifetime,
        discovered_peer: ndp_detail
            .peer_state
            .as_ref()
            .map(convert_ndp_peer_to_api),
        thread_state: convert_thread_state_to_api(
            ndp_detail.thread_state.as_ref(),
        ),
    }))
}

pub async fn get_ndp_interface_detail(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NdpInterfaceSelector>,
) -> Result<HttpResponseOk<NdpInterface>, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();

    let neighbor = ctx
        .db
        .get_unnumbered_bgp_neighbors()
        .map_err(|e| {
            HttpError::for_internal_error(format!(
                "failed to get unnumbered neighbors: {e}"
            ))
        })?
        .into_iter()
        .find(|n| n.interface == rq.interface_name)
        .ok_or_else(|| {
            HttpError::for_not_found(
                None,
                format!(
                    "no unnumbered neighbor on interface {}",
                    rq.interface_name
                ),
            )
        })?;

    ndp_interface_detail(ctx, &neighbor)
}

pub async fn get_ndp_interface_detail_v5(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<v5::ndp::NdpInterfaceSelector>,
) -> Result<HttpResponseOk<NdpInterface>, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();

    // Prior form: scope the lookup to the requested ASN.
    let neighbor = ctx
        .db
        .get_unnumbered_bgp_neighbors()
        .map_err(|e| {
            HttpError::for_internal_error(format!(
                "failed to get unnumbered neighbors: {e}"
            ))
        })?
        .into_iter()
        .find(|n| n.asn == rq.asn && n.interface == rq.interface)
        .ok_or_else(|| {
            HttpError::for_not_found(
                None,
                format!(
                    "no unnumbered neighbor for ASN {} on interface {}",
                    rq.asn, rq.interface
                ),
            )
        })?;

    ndp_interface_detail(ctx, &neighbor)
}
