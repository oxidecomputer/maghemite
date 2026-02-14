// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(clippy::type_complexity)]
use crate::unnumbered_manager::{
    NdpPeerState, NdpThreadStateInternal, UnnumberedManagerNdp,
};
use crate::validation::{
    validate_prefixes, validate_prefixes_v4, validate_prefixes_v6,
};
use crate::{admin::HandlerContext, error::Error, log::bgp_log};
use bgp::{
    BGP_PORT,
    config::RouterConfig,
    connection::BgpConnection,
    connection_tcp::BgpConnectionTcp,
    messages::Afi,
    params::*,
    router::{LoadPolicyError, Router},
    session::{
        AdminEvent, ConnectionKind, FsmEvent, FsmEventRecord, FsmStateKind,
        MessageHistory, MessageHistoryV1, PeerId, SessionEndpoint, SessionInfo,
        SessionRunner,
    },
};
use chrono::{DateTime, SecondsFormat, Utc};
use dropshot::{
    ClientErrorStatusCode, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use mg_api::{
    AsnSelector, BestpathFanoutRequest, BestpathFanoutResponse,
    ExportedSelector, FsmEventBuffer, FsmHistoryRequest, FsmHistoryRequestV4,
    FsmHistoryResponse, FsmHistoryResponseV4, MessageDirection,
    MessageHistoryRequest, MessageHistoryRequestV1, MessageHistoryRequestV4,
    MessageHistoryResponse, MessageHistoryResponseV1, MessageHistoryResponseV4,
    NdpInterface, NdpInterfaceSelector, NdpManagerState, NdpPeer,
    NdpPendingInterface, NdpThreadState, NeighborResetRequest,
    NeighborResetRequestV1, NeighborSelector, NeighborSelectorV1, RibV1,
    UnnumberedNeighborResetRequest, UnnumberedNeighborSelector,
};
use mg_common::lock;
use rdb::{
    AddressFamily, Asn, BgpRouterInfo, ImportExportPolicy4,
    ImportExportPolicy6, ImportExportPolicyV1, Prefix, Prefix4, Prefix6,
};
use slog::Logger;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{
    Arc, Mutex,
    mpsc::{Sender, channel},
};
use std::time::{Duration, Instant, SystemTime};

const UNIT_BGP: &str = "bgp";
const DEFAULT_BGP_LISTEN: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BGP_PORT, 0, 0));

#[derive(Clone)]
pub struct BgpContext {
    pub(crate) router: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    peer_to_session:
        Arc<Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionTcp>>>>,
    pub(crate) unnumbered_manager: Arc<UnnumberedManagerNdp>,
}

impl BgpContext {
    pub fn new(
        peer_to_session: Arc<
            Mutex<BTreeMap<PeerId, SessionEndpoint<BgpConnectionTcp>>>,
        >,
        log: Logger,
    ) -> Self {
        let router = Arc::new(Mutex::new(BTreeMap::new()));
        let unnumbered_manager = UnnumberedManagerNdp::new(router.clone(), log);
        Self {
            router,
            peer_to_session,
            unnumbered_manager,
        }
    }
}

macro_rules! get_router {
    ($ctx:expr, $asn:expr) => {
        lock!($ctx.bgp.router)
            .get(&$asn)
            .ok_or(Error::NotFound("no bgp router configured".into()))
    };
}

pub async fn read_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<bgp::params::Router>>, HttpError> {
    let ctx = ctx.context();
    let routers = ctx
        .db
        .get_bgp_routers()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;
    let mut result = Vec::new();

    for (asn, info) in routers.iter() {
        result.push(bgp::params::Router {
            asn: *asn,
            id: info.id,
            listen: info.listen.clone(),
            graceful_shutdown: info.graceful_shutdown,
        });
    }

    Ok(HttpResponseOk(result))
}

pub async fn create_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<bgp::params::Router>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    let mut guard = lock!(ctx.bgp.router);
    if guard.get(&rq.asn).is_some() {
        return Err(HttpError::for_client_error_with_status(
            Some("bgp router with specified ASN exists".into()),
            ClientErrorStatusCode::CONFLICT,
        ));
    }

    Ok(helpers::add_router(ctx.clone(), rq, &mut guard)?)
}

pub async fn read_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<bgp::params::Router>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    let routers = ctx
        .db
        .get_bgp_routers()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    let info = routers.get(&rq.asn).ok_or(HttpError::for_not_found(
        None,
        format!("asn: {} not found in db", rq.asn),
    ))?;

    Ok(HttpResponseOk(bgp::params::Router {
        asn: rq.asn,
        id: info.id,
        listen: info.listen.clone(),
        graceful_shutdown: info.graceful_shutdown,
    }))
}

pub async fn update_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<bgp::params::Router>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    Ok(helpers::ensure_router(ctx.clone(), rq).await?)
}

pub async fn delete_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let db = ctx.db.clone();

    db.remove_bgp_router(rq.asn)
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    let mut routers = lock!(ctx.bgp.router);
    if let Some(r) = routers.remove(&rq.asn) {
        r.shutdown()
    };

    Ok(HttpResponseUpdatedNoContent())
}

// Neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pub async fn read_neighbors_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let nbrs = ctx
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| Neighbor::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

pub async fn read_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<NeighborV1>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let nbrs = ctx
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| NeighborV1::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

pub async fn create_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor_v1(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelectorV1>,
) -> Result<HttpResponseOk<NeighborV1>, HttpError> {
    let rq = request.into_inner();
    let db_neighbors = ctx.context().db.get_bgp_neighbors().map_err(|e| {
        HttpError::for_internal_error(format!("get neighbors kv tree: {e}"))
    })?;
    let neighbor_info = db_neighbors
        .iter()
        .find(|n| n.host.ip() == rq.addr)
        .ok_or(HttpError::for_not_found(
            None,
            format!("neighbor {} not found in db", rq.addr),
        ))?;

    let result = NeighborV1::from_rdb_neighbor_info(rq.asn, neighbor_info);
    Ok(HttpResponseOk(result))
}

pub async fn update_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor_v1(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelectorV1>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

// Legacy API handler - hardcoded to IPv4 for backwards compatibility
pub async fn clear_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborResetRequestV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    Ok(helpers::reset_neighbor(ctx.clone(), rq.into()).await?)
}

// V2 API handler - supports per-AF operations
pub async fn clear_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NeighborResetRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::reset_neighbor(ctx.clone(), rq).await?)
}

pub async fn create_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelectorV1>,
) -> Result<HttpResponseOk<Neighbor>, HttpError> {
    let rq = request.into_inner();
    let db_neighbors = ctx.context().db.get_bgp_neighbors().map_err(|e| {
        HttpError::for_internal_error(format!("get neighbors kv tree: {e}"))
    })?;
    let neighbor_info = db_neighbors
        .iter()
        .find(|n| n.host.ip() == rq.addr)
        .ok_or(HttpError::for_not_found(
            None,
            format!("neighbor {} not found in db", rq.addr),
        ))?;

    let result = Neighbor::from_rdb_neighbor_info(rq.asn, neighbor_info);
    Ok(HttpResponseOk(result))
}

pub async fn update_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    helpers::add_neighbor(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_neighbor_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NeighborSelectorV1>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

// V3 API - Unified neighbor operations supporting both numbered and unnumbered
pub async fn create_neighbor_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    // Delegate to v2 - create operation doesn't depend on selector type
    create_neighbor_v2(ctx, request).await
}

pub async fn read_neighbor_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<NeighborSelector>,
) -> Result<HttpResponseOk<Neighbor>, HttpError> {
    let rq = path.into_inner();
    let peer_id = rq.to_peer_id();

    match peer_id {
        PeerId::Ip(addr) => {
            // Numbered peer - query numbered neighbors DB
            let db_neighbors =
                ctx.context().db.get_bgp_neighbors().map_err(|e| {
                    HttpError::for_internal_error(format!(
                        "get neighbors kv tree: {e}"
                    ))
                })?;
            let neighbor_info = db_neighbors
                .iter()
                .find(|n| n.host.ip() == addr)
                .ok_or(HttpError::for_not_found(
                    None,
                    format!("neighbor {} not found in db", addr),
                ))?;
            let result =
                Neighbor::from_rdb_neighbor_info(rq.asn, neighbor_info);
            Ok(HttpResponseOk(result))
        }
        PeerId::Interface(ref iface) => {
            // Unnumbered peer - query unnumbered neighbors DB
            let db_neighbors =
                ctx.context().db.get_unnumbered_bgp_neighbors().map_err(
                    |e| {
                        HttpError::for_internal_error(format!(
                            "get unnumbered neighbors kv tree: {e}"
                        ))
                    },
                )?;
            let neighbor_info = db_neighbors
                .iter()
                .find(|n| &n.interface == iface)
                .ok_or(HttpError::for_not_found(
                    None,
                    format!("neighbor {} not found in db", iface),
                ))?;
            let result = UnnumberedNeighbor::from_rdb_neighbor_info(
                rq.asn,
                neighbor_info,
            );
            // Convert UnnumberedNeighbor to Neighbor
            Ok(HttpResponseOk(Neighbor {
                asn: result.asn,
                name: result.name,
                group: result.group,
                host: std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                    179,
                ),
                parameters: result.parameters,
            }))
        }
    }
}

pub async fn read_neighbors_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<AsnSelector>,
) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError> {
    let rq = path.into_inner();
    let ctx = ctx.context();

    let nbrs = ctx
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| Neighbor::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

pub async fn update_neighbor_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Neighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    // Delegate to v2 - update operation doesn't depend on selector type
    update_neighbor_v2(ctx, request).await
}

pub async fn delete_neighbor_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    path: Path<NeighborSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = path.into_inner();
    let peer_id = rq.to_peer_id();
    let ctx = ctx.context();

    match peer_id {
        PeerId::Ip(addr) => {
            Ok(helpers::remove_neighbor(ctx.clone(), rq.asn, addr).await?)
        }
        PeerId::Interface(ref iface) => Ok(
            helpers::remove_unnumbered_neighbor(ctx.clone(), rq.asn, iface)
                .await?,
        ),
    }
}

// Unnumbered neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pub async fn read_unnumbered_neighbors(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<UnnumberedNeighbor>>, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();

    let nbrs = ctx
        .db
        .get_unnumbered_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let result = nbrs
        .into_iter()
        .filter(|x| x.asn == rq.asn)
        .map(|x| UnnumberedNeighbor::from_rdb_neighbor_info(rq.asn, &x))
        .collect();

    Ok(HttpResponseOk(result))
}

pub async fn create_unnumbered_neighbor(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<UnnumberedNeighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();
    helpers::add_unnumbered_neighbor(ctx.clone(), rq, false)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_unnumbered_neighbor(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<UnnumberedNeighborSelector>,
) -> Result<HttpResponseOk<UnnumberedNeighbor>, HttpError> {
    let rq = request.into_inner();
    let db_neighbors = rqctx
        .context()
        .db
        .get_unnumbered_bgp_neighbors()
        .map_err(|e| {
            HttpError::for_internal_error(format!("get neighbors kv tree: {e}"))
        })?;
    let neighbor_info = db_neighbors
        .iter()
        .find(|n| n.interface == rq.interface)
        .ok_or(HttpError::for_not_found(
            None,
            format!("neighbor {} not found in db", rq.interface),
        ))?;

    let result =
        UnnumberedNeighbor::from_rdb_neighbor_info(rq.asn, neighbor_info);
    Ok(HttpResponseOk(result))
}

pub async fn update_unnumbered_neighbor(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<UnnumberedNeighbor>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();
    helpers::add_unnumbered_neighbor(ctx.clone(), rq, true)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_unnumbered_neighbor(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<UnnumberedNeighborSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();
    Ok(
        helpers::remove_unnumbered_neighbor(ctx.clone(), rq.asn, &rq.interface)
            .await?,
    )
}

pub async fn clear_unnumbered_neighbor(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<UnnumberedNeighborResetRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();
    Ok(helpers::reset_unnumbered_neighbor(
        ctx.clone(),
        rq.asn,
        &rq.interface,
        rq.op,
    )
    .await?)
}

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
    _request: Query<AsnSelector>,
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

pub async fn get_ndp_interfaces(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Vec<NdpInterface>>, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();

    // Get all unnumbered neighbors for this ASN
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

    // Get NDP state for managed interfaces
    let ndp_state = ctx.bgp.unnumbered_manager.list_ndp_interfaces();

    // Build response by matching neighbors to NDP state
    let mut result = Vec::new();
    for neighbor in unnumbered_neighbors {
        // Find NDP state for this interface
        if let Some(ndp) = ndp_state
            .iter()
            .find(|info| info.interface == neighbor.interface)
        {
            let discovered_peer =
                ndp.peer_state.as_ref().map(convert_ndp_peer_to_api);
            let thread_state =
                convert_thread_state_to_api(ndp.thread_state.as_ref());

            result.push(NdpInterface {
                interface: neighbor.interface.clone(),
                local_address: ndp.local_address,
                scope_id: ndp.scope_id,
                router_lifetime: neighbor.router_lifetime,
                discovered_peer,
                thread_state,
            });
        }
    }

    Ok(HttpResponseOk(result))
}

pub async fn get_ndp_interface_detail(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: Query<NdpInterfaceSelector>,
) -> Result<HttpResponseOk<NdpInterface>, HttpError> {
    let rq = request.into_inner();
    let ctx = rqctx.context();

    // Verify this interface has an unnumbered neighbor configured for this ASN
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

    // Get detailed NDP state
    let unnumbered_manager = &ctx.bgp.unnumbered_manager;

    let ndp_detail = unnumbered_manager
        .get_ndp_interface_detail(&rq.interface)
        .map_err(|e| {
            HttpError::for_internal_error(format!(
                "failed to get NDP state: {e}"
            ))
        })?
        .ok_or_else(|| {
            HttpError::for_not_found(
                None,
                format!("interface {} not managed by NDP", rq.interface),
            )
        })?;

    let discovered_peer =
        ndp_detail.peer_state.as_ref().map(convert_ndp_peer_to_api);
    let thread_state =
        convert_thread_state_to_api(ndp_detail.thread_state.as_ref());

    Ok(HttpResponseOk(NdpInterface {
        interface: rq.interface,
        local_address: ndp_detail.local_address,
        scope_id: ndp_detail.scope_id,
        router_lifetime: neighbor.router_lifetime,
        discovered_peer,
        thread_state,
    }))
}

// IPv4 origin ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pub async fn create_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin4>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v4(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .create_origin(AddressFamily::Ipv4, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Origin4>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let originated = get_router!(ctx, rq.asn)?
        .db
        .get_origin(Some(AddressFamily::Ipv4))
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let mut prefixes: Vec<Prefix4> = originated
        .into_iter()
        .filter_map(|p| match p {
            Prefix::V4(p4) => Some(p4),
            _ => None,
        })
        .collect();

    // stable output order for clients
    prefixes.sort();

    Ok(HttpResponseOk(Origin4 {
        asn: rq.asn,
        prefixes,
    }))
}

pub async fn update_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin4>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v4(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .set_origin(AddressFamily::Ipv4, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_origin4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .clear_origin(AddressFamily::Ipv4)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseDeleted())
}

pub async fn create_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin6>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v6(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .create_origin(AddressFamily::Ipv6, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn read_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<Origin6>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let originated = get_router!(ctx, rq.asn)?
        .db
        .get_origin(Some(AddressFamily::Ipv6))
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let mut prefixes: Vec<Prefix6> = originated
        .into_iter()
        .filter_map(|p| match p {
            Prefix::V6(p6) => Some(p6),
            _ => None,
        })
        .collect();

    // stable output order for clients
    prefixes.sort();

    Ok(HttpResponseOk(Origin6 {
        asn: rq.asn,
        prefixes,
    }))
}

pub async fn update_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Origin6>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    // Validate prefixes before processing
    validate_prefixes_v6(&rq.prefixes)?;

    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .set_origin(AddressFamily::Ipv6, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn delete_origin6(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .clear_origin(AddressFamily::Ipv6)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseDeleted())
}

// Legacy endpoint (pre MP-BGP/unnumbered): IPv4 only, no filtering
pub async fn get_exported(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let r = get_router!(ctx, rq.asn)?.clone();
    let orig4 = r.db.get_origin(Some(AddressFamily::Ipv4)).map_err(|e| {
        HttpError::for_internal_error(format!("error getting origin: {e}"))
    })?;
    let neighs = r.db.get_bgp_neighbors().map_err(|e| {
        HttpError::for_internal_error(format!("error getting neighbors: {e}"))
    })?;
    let mut exported = HashMap::new();

    for n in neighs {
        let ip = n.host.ip();

        if !ip.is_ipv4() {
            continue;
        }

        if r.get_session(ip)
            .filter(|s| s.state() == FsmStateKind::Established)
            .is_none()
        {
            continue;
        }

        let mut orig_routes: Vec<Prefix> = orig4.clone();

        // Combine per-AF export policies into legacy format for filtering
        let allow_export = ImportExportPolicyV1::from_per_af_policies(
            &n.parameters.allow_export4,
            &n.parameters.allow_export6,
        );
        let mut exported_routes: Vec<Prefix> = match allow_export {
            ImportExportPolicyV1::NoFiltering => orig_routes,
            ImportExportPolicyV1::Allow(epol) => {
                orig_routes.retain(|p| epol.contains(p));
                orig_routes
            }
        };

        // stable output order for clients
        exported_routes.sort();
        exported.insert(n.host.ip(), exported_routes);
    }

    Ok(HttpResponseOk(exported))
}

// MP-BGP + BGP unnumbered
pub async fn get_exported_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ExportedSelector>,
) -> Result<HttpResponseOk<HashMap<PeerId, Vec<Prefix>>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let r = get_router!(ctx, rq.asn)?.clone();

    // Get originated prefixes for both address families
    let orig4 = r.db.get_origin(Some(AddressFamily::Ipv4)).map_err(|e| {
        HttpError::for_internal_error(format!("error getting origin4: {e}"))
    })?;
    let orig6 = r.db.get_origin(Some(AddressFamily::Ipv6)).map_err(|e| {
        HttpError::for_internal_error(format!("error getting origin6: {e}"))
    })?;

    // Determine which address families to process
    let process_ipv4 = rq.afi.is_none() || rq.afi == Some(Afi::Ipv4);
    let process_ipv6 = rq.afi.is_none() || rq.afi == Some(Afi::Ipv6);

    let mut exported = HashMap::new();

    if let Some(ref peer_filter) = rq.peer {
        // Specific peer requested - look it up directly
        if let Some(session) = r.get_session(peer_filter.clone())
            && let Some((peer_key, routes)) = helpers::get_exported(
                &session,
                &orig4,
                &orig6,
                process_ipv4,
                process_ipv6,
            )
        {
            exported.insert(peer_key, routes);
        }
    } else {
        // No peer filter - iterate all sessions
        for session in lock!(r.sessions).values() {
            if let Some((peer_key, routes)) = helpers::get_exported(
                session,
                &orig4,
                &orig6,
                process_ipv4,
                process_ipv6,
            ) {
                exported.insert(peer_key, routes);
            }
        }
    }

    Ok(HttpResponseOk(exported))
}

// Fixed version: uses String keys from PeerId Display for JSON compatibility
pub async fn get_exported_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ExportedSelector>,
) -> Result<HttpResponseOk<HashMap<String, Vec<Prefix>>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let r = get_router!(ctx, rq.asn)?.clone();

    // Determine which address families to process
    let process_ipv4 = rq.afi.is_none() || rq.afi == Some(Afi::Ipv4);
    let process_ipv6 = rq.afi.is_none() || rq.afi == Some(Afi::Ipv6);

    // Only query originated prefixes for requested address families
    let orig4 = if process_ipv4 {
        r.db.get_origin(Some(AddressFamily::Ipv4)).map_err(|e| {
            HttpError::for_internal_error(format!("error getting origin4: {e}"))
        })?
    } else {
        Vec::new()
    };
    let orig6 = if process_ipv6 {
        r.db.get_origin(Some(AddressFamily::Ipv6)).map_err(|e| {
            HttpError::for_internal_error(format!("error getting origin6: {e}"))
        })?
    } else {
        Vec::new()
    };

    let mut exported = HashMap::new();

    if let Some(ref peer_filter) = rq.peer {
        // Specific peer requested - look it up directly
        if let Some(session) = r.get_session(peer_filter.clone())
            && let Some((peer_key, routes)) = helpers::get_exported(
                &session,
                &orig4,
                &orig6,
                process_ipv4,
                process_ipv6,
            )
        {
            exported.insert(peer_key.to_string(), routes);
        }
    } else {
        // No peer filter - iterate all sessions
        for session in lock!(r.sessions).values() {
            if let Some((peer_key, routes)) = helpers::get_exported(
                session,
                &orig4,
                &orig6,
                process_ipv4,
                process_ipv6,
            ) {
                exported.insert(peer_key.to_string(), routes);
            }
        }
    }

    Ok(HttpResponseOk(exported))
}

// Pre-UNNUMBERED versions (BgpPathProperties.peer is IpAddr)
pub async fn get_imported_v1(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<RibV1>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let imported = get_router!(ctx, rq.asn)?
        .db
        .full_rib(Some(AddressFamily::Ipv4));
    Ok(HttpResponseOk(imported.into()))
}

pub async fn get_selected_v1(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AsnSelector>,
) -> Result<HttpResponseOk<RibV1>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let selected = get_router!(ctx, rq.asn)?
        .db
        .loc_rib(Some(AddressFamily::Ipv4));
    Ok(HttpResponseOk(selected.into()))
}

pub async fn get_neighbors(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();
    let routers = lock!(ctx.bgp.router);
    let r = routers
        .get(&rq.asn)
        .ok_or(HttpError::for_not_found(None, "ASN not found".to_string()))?;

    for s in lock!(r.sessions).values() {
        let dur =
            s.current_state_duration().as_millis().min(u64::MAX as u128) as u64;

        // If the session runner has a primary connection, pull the config and
        // runtime state from it. If not, just use the config owned by the
        // session runner as both the config and runtime state.
        let (conf_holdtime, neg_holdtime, conf_keepalive, neg_keepalive) =
            if let Some(primary) = s.primary_connection() {
                let clock = primary.connection().clock();
                (
                    clock.timers.config_hold_time,
                    lock!(clock.timers.hold).interval,
                    clock.timers.config_keepalive_time,
                    lock!(clock.timers.keepalive).interval,
                )
            } else {
                let session_info = lock!(s.session);
                (
                    session_info.hold_time,
                    session_info.hold_time,
                    session_info.keepalive_time,
                    session_info.keepalive_time,
                )
            };

        let pi = PeerInfoV2 {
            state: s.state(),
            asn: s.remote_asn(),
            duration_millis: dur,
            timers: PeerTimersV1 {
                hold: DynamicTimerInfoV1 {
                    configured: conf_holdtime,
                    negotiated: neg_holdtime,
                },
                keepalive: DynamicTimerInfoV1 {
                    configured: conf_keepalive,
                    negotiated: neg_keepalive,
                },
            },
        };

        let peer_ip = match s.neighbor.peer {
            PeerId::Ip(ip) => ip,
            PeerId::Interface(_) => continue, // Skip unnumbered sessions for V1 API
        };
        peers.insert(peer_ip, PeerInfoV1::from(pi));
    }

    Ok(HttpResponseOk(peers))
}

pub async fn get_neighbors_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();
    let routers = lock!(ctx.bgp.router);
    let r = routers
        .get(&rq.asn)
        .ok_or(HttpError::for_not_found(None, "ASN not found".to_string()))?;

    for s in lock!(r.sessions).values() {
        let dur =
            s.current_state_duration().as_millis().min(u64::MAX as u128) as u64;

        let (conf_holdtime, neg_holdtime, conf_keepalive, neg_keepalive) =
            if let Some(primary) = s.primary_connection() {
                let clock = primary.connection().clock();
                (
                    clock.timers.config_hold_time,
                    lock!(clock.timers.hold).interval,
                    clock.timers.config_keepalive_time,
                    lock!(clock.timers.keepalive).interval,
                )
            } else {
                let session_info = lock!(s.session);
                (
                    session_info.hold_time,
                    session_info.hold_time,
                    session_info.keepalive_time,
                    session_info.keepalive_time,
                )
            };

        let peer_ip = match s.neighbor.peer {
            PeerId::Ip(ip) => ip,
            PeerId::Interface(_) => continue, // Skip unnumbered sessions for V2 API
        };
        peers.insert(
            peer_ip,
            PeerInfoV2 {
                state: s.state(),
                asn: s.remote_asn(),
                duration_millis: dur,
                timers: PeerTimersV1 {
                    hold: DynamicTimerInfoV1 {
                        configured: conf_holdtime,
                        negotiated: neg_holdtime,
                    },
                    keepalive: DynamicTimerInfoV1 {
                        configured: conf_keepalive,
                        negotiated: neg_keepalive,
                    },
                },
            },
        );
    }

    Ok(HttpResponseOk(peers))
}

pub async fn get_neighbors_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfo>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();

    // Clone sessions while holding locks, then release them
    let sessions: Vec<_> = {
        let routers = lock!(ctx.bgp.router);
        let r = routers.get(&rq.asn).ok_or(HttpError::for_not_found(
            None,
            "ASN not found".to_string(),
        ))?;
        lock!(r.sessions).values().cloned().collect()
    };

    for s in sessions.iter() {
        let peer_ip = match s.neighbor.peer {
            PeerId::Ip(ip) => ip,
            PeerId::Interface(_) => continue, // Skip unnumbered sessions
        };
        peers.insert(peer_ip, s.get_peer_info());
    }

    Ok(HttpResponseOk(peers))
}

pub async fn get_neighbors_unified(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut peers = HashMap::new();

    // Clone sessions while holding locks, then release them
    let sessions: Vec<_> = {
        let routers = lock!(ctx.bgp.router);
        let r = routers.get(&rq.asn).ok_or(HttpError::for_not_found(
            None,
            "ASN not found".to_string(),
        ))?;
        lock!(r.sessions).values().cloned().collect()
    };

    for s in sessions.iter() {
        // Use PeerId Display impl as HashMap key
        let peer_key = s.neighbor.peer.to_string();
        peers.insert(peer_key, s.get_peer_info());
    }

    Ok(HttpResponseOk(peers))
}

pub async fn bgp_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequestV1>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    // Convert v1 request to current format (hardcodes IPv4-only)
    do_bgp_apply(ctx.context(), ApplyRequest::from(request.into_inner())).await
}

pub async fn bgp_apply_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    do_bgp_apply(ctx.context(), request.into_inner()).await
}

async fn do_bgp_apply(
    ctx: &Arc<HandlerContext>,
    rq: ApplyRequest,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.log.clone();

    // Validate originate prefixes before processing
    validate_prefixes(&rq.originate)?;

    bgp_log!(log, info, "bgp apply: {rq:#?}";
        "params" => format!("{rq:?}")
    );

    #[derive(Debug, Eq)]
    struct Nbr {
        addr: IpAddr,
        asn: u32,
    }

    impl Hash for Nbr {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.addr.hash(state);
        }
    }

    impl PartialEq for Nbr {
        fn eq(&self, other: &Nbr) -> bool {
            self.addr.eq(&other.addr)
        }
    }

    #[derive(Debug, Eq)]
    struct Unbr {
        interface: String,
        asn: u32,
    }

    impl Hash for Unbr {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.interface.hash(state);
        }
    }

    impl PartialEq for Unbr {
        fn eq(&self, other: &Unbr) -> bool {
            self.interface.eq(&other.interface)
        }
    }

    let groups = ctx
        .db
        .get_bgp_neighbors()
        .map_err(Error::Db)?
        .into_iter()
        .map(|x| x.group)
        .collect::<HashSet<_>>();

    // Turn any peer groups that are resident in the db but not in the apply
    // request into empty groups so the difference functions below remove
    // any peers from entire groups that have been removed.
    let mut peers = rq.peers.clone();
    for g in &groups {
        if !peers.contains_key(g) {
            peers.insert(g.clone(), Vec::default());
        }
    }
    let mut upeers = rq.unnumbered_peers.clone();
    for g in &groups {
        if !upeers.contains_key(g) {
            upeers.insert(g.clone(), Vec::default());
        }
    }

    helpers::ensure_router(
        ctx.clone(),
        bgp::params::Router {
            asn: rq.asn,
            id: rq.asn,
            listen: DEFAULT_BGP_LISTEN.to_string(), //TODO as parameter
            graceful_shutdown: false,               // TODO as parameter
        },
    )
    .await?;

    for (group, peers) in &upeers {
        let current: Vec<rdb::BgpUnnumberedNeighborInfo> = ctx
            .db
            .get_unnumbered_bgp_neighbors()
            .map_err(Error::Db)?
            .into_iter()
            .filter(|x| &x.group == group)
            .collect();

        let current_unbr_ifxs: HashSet<Unbr> = current
            .iter()
            .map(|x| Unbr {
                interface: x.interface.clone(),
                asn: x.asn,
            })
            .collect();

        let specified_unbr_ifxs: HashSet<Unbr> = peers
            .iter()
            .map(|x| Unbr {
                interface: x.interface.clone(),
                asn: rq.asn,
            })
            .collect();

        let to_delete = current_unbr_ifxs.difference(&specified_unbr_ifxs);
        let to_add = specified_unbr_ifxs.difference(&current_unbr_ifxs);
        let to_modify = current_unbr_ifxs.intersection(&specified_unbr_ifxs);

        bgp_log!(log, info, "unbr: current {current:#?}");
        bgp_log!(log, info, "unbr: adding {to_add:#?}");
        bgp_log!(log, info, "unbr: removing {to_delete:#?}");

        let mut nbr_config = Vec::new();
        for nbr in to_add {
            let cfg = peers
                .iter()
                .find(|x| x.interface == nbr.interface)
                .ok_or(Error::NotFound(nbr.interface.clone()))?;
            nbr_config.push((nbr, cfg));
        }

        for nbr in to_modify {
            let spec = peers
                .iter()
                .find(|x| x.interface == nbr.interface)
                .ok_or(Error::NotFound(nbr.interface.clone()))?;

            let tgt = UnnumberedNeighbor::from_bgp_peer_config(
                nbr.asn,
                group.clone(),
                spec.clone(),
            );

            let curr = UnnumberedNeighbor::from_rdb_neighbor_info(
                nbr.asn,
                current
                    .iter()
                    .find(|x| x.interface == nbr.interface)
                    .ok_or(Error::NotFound(nbr.interface.clone()))?,
            );

            if tgt != curr {
                nbr_config.push((nbr, spec));
            }
        }

        for (nbr, cfg) in nbr_config {
            helpers::add_unnumbered_neighbor(
                ctx.clone(),
                UnnumberedNeighbor::from_bgp_peer_config(
                    nbr.asn,
                    group.clone(),
                    cfg.clone(),
                ),
                true, // ensure mode: create or update as needed
            )?;
        }

        for nbr in to_delete {
            helpers::remove_unnumbered_neighbor(
                ctx.clone(),
                nbr.asn,
                &nbr.interface,
            )
            .await?;

            let mut routers = lock!(ctx.bgp.router);
            let mut remove = false;
            if let Some(r) = routers.get(&nbr.asn) {
                remove = lock!(r.sessions).is_empty();
            }
            if remove && let Some(r) = routers.remove(&nbr.asn) {
                r.shutdown()
            };
        }
    }

    for (group, peers) in &peers {
        let current: Vec<rdb::BgpNeighborInfo> = ctx
            .db
            .get_bgp_neighbors()
            .map_err(Error::Db)?
            .into_iter()
            .filter(|x| &x.group == group)
            .collect();

        let current_nbr_addrs: HashSet<Nbr> = current
            .iter()
            .map(|x| Nbr {
                addr: x.host.ip(),
                asn: x.asn,
            })
            .collect();

        let specified_nbr_addrs: HashSet<Nbr> = peers
            .iter()
            .map(|x| Nbr {
                addr: x.host.ip(),
                asn: rq.asn,
            })
            .collect();

        let to_delete = current_nbr_addrs.difference(&specified_nbr_addrs);
        let to_add = specified_nbr_addrs.difference(&current_nbr_addrs);
        let to_modify = current_nbr_addrs.intersection(&specified_nbr_addrs);

        bgp_log!(log, info, "nbr: current {current:#?}");
        bgp_log!(log, info, "nbr: adding {to_add:#?}");
        bgp_log!(log, info, "nbr: removing {to_delete:#?}");

        let mut nbr_config = Vec::new();
        for nbr in to_add {
            let cfg = peers
                .iter()
                .find(|x| x.host.ip() == nbr.addr)
                .ok_or(Error::NotFound(nbr.addr.to_string()))?;
            nbr_config.push((nbr, cfg));
        }

        for nbr in to_modify {
            let spec = peers
                .iter()
                .find(|x| x.host.ip() == nbr.addr)
                .ok_or(Error::NotFound(nbr.addr.to_string()))?;

            let tgt = Neighbor::from_bgp_peer_config(
                nbr.asn,
                group.clone(),
                spec.clone(),
            );

            let curr = Neighbor::from_rdb_neighbor_info(
                nbr.asn,
                current
                    .iter()
                    .find(|x| x.host.ip() == nbr.addr)
                    .ok_or(Error::NotFound(nbr.addr.to_string()))?,
            );

            if tgt != curr {
                nbr_config.push((nbr, spec));
            }
        }

        // TODO all the db modification that happens below needs to happen in a
        // transaction.

        for (nbr, cfg) in nbr_config {
            helpers::add_neighbor(
                ctx.clone(),
                Neighbor::from_bgp_peer_config(
                    nbr.asn,
                    group.clone(),
                    cfg.clone(),
                ),
                true,
            )?;
        }

        for nbr in to_delete {
            helpers::remove_neighbor(ctx.clone(), nbr.asn, nbr.addr).await?;

            let mut routers = lock!(ctx.bgp.router);
            let mut remove = false;
            if let Some(r) = routers.get(&nbr.asn) {
                remove = lock!(r.sessions).is_empty();
            }
            if remove && let Some(r) = routers.remove(&nbr.asn) {
                r.shutdown()
            };
        }
    }

    get_router!(ctx, rq.asn)?
        .set_origin(
            AddressFamily::Ipv4,
            rq.originate.clone().into_iter().collect(),
        )
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    get_router!(ctx, rq.asn)?
        .set_origin(
            AddressFamily::Ipv6,
            rq.originate.clone().into_iter().collect(),
        )
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

// Helper for fetching message history with PeerId filtering
// Returns HashMap with string keys using PeerId Display format
fn get_message_history_filtered(
    ctx: &Arc<HandlerContext>,
    asn: u32,
    peer: Option<PeerId>,
    direction: Option<MessageDirection>,
) -> Result<HashMap<String, MessageHistory>, HttpError> {
    let mut result = HashMap::new();

    // Determine which peers to fetch history for
    let peers_to_query: Vec<PeerId> = if let Some(peer_id) = peer {
        if lock!(get_router!(ctx, asn)?.sessions).contains_key(&peer_id) {
            vec![peer_id]
        } else {
            vec![]
        }
    } else {
        lock!(get_router!(ctx, asn)?.sessions)
            .keys()
            .cloned()
            .collect()
    };

    // Fetch history for each peer
    for peer_id in peers_to_query {
        if let Some(session) =
            lock!(get_router!(ctx, asn)?.sessions).get(&peer_id)
        {
            let mut history = lock!(session.message_history).clone();

            // Apply direction filter if specified
            if let Some(dir) = direction {
                match dir {
                    MessageDirection::Sent => {
                        history.received.clear();
                    }
                    MessageDirection::Received => {
                        history.sent.clear();
                    }
                }
            }

            // Use PeerId Display impl as HashMap key
            result.insert(peer_id.to_string(), history);
        }
    }

    Ok(result)
}

pub async fn message_history(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequestV1>,
) -> Result<HttpResponseOk<MessageHistoryResponseV1>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut result = HashMap::new();

    for (key, session) in lock!(get_router!(ctx, rq.asn)?.sessions).iter() {
        // Only include IP-based sessions in the history
        if let PeerId::Ip(addr) = key {
            let mh = lock!(session.message_history).clone();
            result.insert(*addr, MessageHistoryV1::from(mh));
        }
    }

    Ok(HttpResponseOk(MessageHistoryResponseV1 { by_peer: result }))
}

// Pre-UNNUMBERED API endpoint (VERSION_IPV6_BASIC..VERSION_UNNUMBERED)
// Uses IpAddr for numbered peers only
pub async fn message_history_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequestV4>,
) -> Result<HttpResponseOk<MessageHistoryResponseV4>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    // Convert IpAddr filter to PeerId and call unified helper
    let peer_id = rq.peer.map(PeerId::Ip);
    let by_peer_string =
        get_message_history_filtered(ctx, rq.asn, peer_id, rq.direction)?;

    // Convert String keys back to IpAddr (filters out unnumbered peers)
    let by_peer = by_peer_string
        .into_iter()
        .filter_map(|(key, history)| {
            key.parse::<IpAddr>().ok().map(|addr| (addr, history))
        })
        .collect();

    Ok(HttpResponseOk(MessageHistoryResponseV4 { by_peer }))
}

// UNNUMBERED+ API endpoint (VERSION_UNNUMBERED..)
// Uses PeerId enum for both numbered and unnumbered peers
pub async fn message_history_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequest>,
) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let by_peer =
        get_message_history_filtered(ctx, rq.asn, rq.peer, rq.direction)?;
    Ok(HttpResponseOk(MessageHistoryResponse { by_peer }))
}

/// Unified helper for FSM history retrieval.
/// Returns HashMap with String keys (PeerId Display representation).
fn get_fsm_history_filtered(
    ctx: &Arc<HandlerContext>,
    asn: u32,
    peer: Option<PeerId>,
    buffer: Option<FsmEventBuffer>,
) -> Result<HashMap<String, Vec<FsmEventRecord>>, HttpError> {
    let mut result = HashMap::new();
    let use_all_buffer = matches!(buffer, Some(FsmEventBuffer::All));

    if let Some(peer_id) = peer {
        if let Some(session) =
            lock!(get_router!(ctx, asn)?.sessions).get(&peer_id)
        {
            let full_history = lock!(session.fsm_event_history).clone();
            let events = if use_all_buffer {
                full_history.all.into_iter().collect()
            } else {
                full_history.major.into_iter().collect()
            };
            result.insert(peer_id.to_string(), events);
        }
    } else {
        for (peer_id, session) in lock!(get_router!(ctx, asn)?.sessions).iter()
        {
            let full_history = lock!(session.fsm_event_history).clone();
            let events = if use_all_buffer {
                full_history.all.into_iter().collect()
            } else {
                full_history.major.into_iter().collect()
            };
            result.insert(peer_id.to_string(), events);
        }
    }

    Ok(result)
}

// Original API endpoint (VERSION_IPV6_BASIC..VERSION_UNNUMBERED)
// FSM event history for numbered peers only
pub async fn fsm_history(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<FsmHistoryRequestV4>,
) -> Result<HttpResponseOk<FsmHistoryResponseV4>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    // Convert IpAddr filter to PeerId and call unified helper
    let peer_id = rq.peer.map(PeerId::Ip);
    let by_peer_string =
        get_fsm_history_filtered(ctx, rq.asn, peer_id, rq.buffer)?;

    // Convert String keys back to IpAddr (filters out unnumbered peers)
    let by_peer = by_peer_string
        .into_iter()
        .filter_map(|(key, history): (String, Vec<FsmEventRecord>)| {
            key.parse::<IpAddr>().ok().map(|addr| (addr, history))
        })
        .collect();

    Ok(HttpResponseOk(FsmHistoryResponseV4 { by_peer }))
}

// V2 API endpoint (VERSION_UNNUMBERED..)
// FSM event history for all peers (numbered and unnumbered)
pub async fn fsm_history_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<FsmHistoryRequest>,
) -> Result<HttpResponseOk<FsmHistoryResponse>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let by_peer = get_fsm_history_filtered(ctx, rq.asn, rq.peer, rq.buffer)?;
    Ok(HttpResponseOk(FsmHistoryResponse { by_peer }))
}

pub async fn create_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<CheckerSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Checker(rq.code), false)
        .await
}

pub async fn read_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<CheckerSource>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match lock!(ctx.bgp.router).get(&rq.asn) {
        None => Err(HttpError::for_not_found(
            None,
            String::from("ASN not found"),
        )),
        Some(rtr) => match rtr.policy.checker_source() {
            Some(source) => Ok(HttpResponseOk(CheckerSource {
                code: source,
                asn: rq.asn,
            })),
            None => Err(HttpError::for_not_found(
                None,
                String::from("checker source not found"),
            )),
        },
    }
}

pub async fn update_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<CheckerSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Checker(rq.code), true)
        .await
}

pub async fn delete_checker(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::unload_policy(ctx, rq.asn, PolicyKind::Checker).await
}

pub async fn create_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ShaperSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Shaper(rq.code), false)
        .await
}

pub async fn read_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseOk<ShaperSource>, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    match lock!(ctx.bgp.router).get(&rq.asn) {
        None => Err(HttpError::for_not_found(
            None,
            String::from("ASN not found"),
        )),
        Some(rtr) => match rtr.policy.shaper_source() {
            Some(source) => Ok(HttpResponseOk(ShaperSource {
                code: source,
                asn: rq.asn,
            })),
            None => Err(HttpError::for_not_found(
                None,
                String::from("shaper source not found"),
            )),
        },
    }
}

pub async fn update_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ShaperSource>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::load_policy(ctx, rq.asn, PolicySource::Shaper(rq.code), true).await
}

pub async fn delete_shaper(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: Query<AsnSelector>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    helpers::unload_policy(ctx, rq.asn, PolicyKind::Shaper).await
}

pub async fn read_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
    let ctx = ctx.context();
    let fanout = ctx
        .db
        .get_bestpath_fanout()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseOk(BestpathFanoutResponse { fanout }))
}

pub async fn update_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<BestpathFanoutRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    ctx.db
        .set_bestpath_fanout(rq.fanout)
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseUpdatedNoContent())
}

pub(crate) mod helpers {
    use bgp::router::{EnsureSessionResult, UnloadPolicyError};
    use rdb::BgpNeighborParameters;

    use super::*;

    pub(crate) async fn ensure_router(
        ctx: Arc<HandlerContext>,
        rq: bgp::params::Router,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        let mut guard = lock!(ctx.bgp.router);
        if let Some(current) = guard.get(&rq.asn) {
            current.graceful_shutdown(rq.graceful_shutdown)?;
            return Ok(HttpResponseUpdatedNoContent());
        }

        add_router(ctx.clone(), rq, &mut guard)
    }

    pub(crate) async fn remove_neighbor(
        ctx: Arc<HandlerContext>,
        asn: u32,
        addr: IpAddr,
    ) -> Result<HttpResponseDeleted, Error> {
        bgp_log!(ctx.log, info, "remove neighbor (addr {addr}, asn {asn})");

        ctx.db
            .remove_all_prefixes_from_bgp_peer(&PeerId::Ip(addr), None);
        ctx.db.remove_bgp_neighbor(addr)?;
        get_router!(&ctx, asn)?.delete_session(addr);

        Ok(HttpResponseDeleted())
    }

    pub(crate) async fn remove_unnumbered_neighbor(
        ctx: Arc<HandlerContext>,
        asn: u32,
        interface: &str,
    ) -> Result<HttpResponseDeleted, Error> {
        bgp_log!(
            ctx.log,
            info,
            "remove unnumbered neighbor (interface {interface}, asn {asn})"
        );

        // Delete the BGP session for this unnumbered neighbor.
        // Unnumbered sessions are keyed by interface name, not IP address.
        get_router!(&ctx, asn)?
            .delete_session(PeerId::Interface(interface.to_string()));

        // Unregister the interface from NDP peer discovery
        ctx.bgp.unnumbered_manager.remove_interface(interface)?;

        // And now clear out the top level database entry
        ctx.db.remove_unnumbered_bgp_neighbor(interface)?;

        Ok(HttpResponseDeleted())
    }

    pub(crate) fn add_neighbor_v1(
        ctx: Arc<HandlerContext>,
        rq: NeighborV1,
        ensure: bool,
    ) -> Result<(), Error> {
        let log = &ctx.log;
        bgp_log!(log, info, "add neighbor {}", rq.host.ip();
            "params" => format!("{rq:#?}")
        );

        let (event_tx, event_rx) = channel();

        // V1 API is IPv4-only; extract only IPv4 policies
        let allow_import4 = rq.parameters.allow_import.as_ipv4_policy();
        let allow_export4 = rq.parameters.allow_export.as_ipv4_policy();

        let info = SessionInfo::from(&rq.parameters);

        let start_session = if ensure {
            match get_router!(&ctx, rq.asn)?.ensure_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )? {
                EnsureSessionResult::New(_) => true,
                EnsureSessionResult::Updated(_) => false,
            }
        } else {
            get_router!(&ctx, rq.asn)?.new_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )?;
            true
        };

        ctx.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
            asn: rq.asn,
            name: rq.name.clone(),
            group: rq.group.clone(),
            host: rq.host,
            parameters: BgpNeighborParameters {
                hold_time: rq.parameters.hold_time,
                idle_hold_time: rq.parameters.idle_hold_time,
                delay_open: rq.parameters.delay_open,
                passive: rq.parameters.passive,
                connect_retry: rq.parameters.connect_retry,
                keepalive: rq.parameters.keepalive,
                resolution: rq.parameters.resolution,
                remote_asn: rq.parameters.remote_asn,
                min_ttl: rq.parameters.min_ttl,
                md5_auth_key: rq.parameters.md5_auth_key,
                multi_exit_discriminator: rq
                    .parameters
                    .multi_exit_discriminator,
                communities: rq.parameters.communities,
                local_pref: rq.parameters.local_pref,
                enforce_first_as: rq.parameters.enforce_first_as,
                allow_import4,
                allow_export4,
                vlan_id: rq.parameters.vlan_id,

                // V1 API is IPv4-only and doesn't support nexthop override
                ipv4_enabled: true,
                ipv6_enabled: false,
                allow_import6: ImportExportPolicy6::NoFiltering,
                allow_export6: ImportExportPolicy6::NoFiltering,
                nexthop4: None,
                nexthop6: None,
            },
        })?;

        if start_session {
            start_bgp_session(&event_tx)?;
        }

        Ok(())
    }

    pub(crate) fn add_neighbor(
        ctx: Arc<HandlerContext>,
        rq: Neighbor,
        ensure: bool,
    ) -> Result<(), Error> {
        let log = &ctx.log;
        bgp_log!(log, info, "add neighbor {}", rq.host.ip();
            "params" => format!("{rq:#?}")
        );

        // Validate that at least one AF is enabled
        rq.validate_address_families()
            .map_err(Error::InvalidRequest)?;

        let (event_tx, event_rx) = channel();

        let info = SessionInfo::from(&rq.parameters);

        let start_session = if ensure {
            match get_router!(&ctx, rq.asn)?.ensure_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )? {
                EnsureSessionResult::New(_) => true,
                EnsureSessionResult::Updated(_) => false,
            }
        } else {
            get_router!(&ctx, rq.asn)?.new_session(
                rq.clone().into(),
                None,
                event_tx.clone(),
                event_rx,
                info,
            )?;
            true
        };

        // Extract per-AF policies and nexthop for database storage
        let (allow_import4, allow_export4, nexthop4) =
            match &rq.parameters.ipv4_unicast {
                Some(cfg) => (
                    cfg.import_policy.clone(),
                    cfg.export_policy.clone(),
                    cfg.nexthop,
                ),
                None => (
                    ImportExportPolicy4::NoFiltering,
                    ImportExportPolicy4::NoFiltering,
                    None,
                ),
            };

        let (allow_import6, allow_export6, nexthop6) =
            match &rq.parameters.ipv6_unicast {
                Some(cfg) => (
                    cfg.import_policy.clone(),
                    cfg.export_policy.clone(),
                    cfg.nexthop,
                ),
                None => (
                    ImportExportPolicy6::NoFiltering,
                    ImportExportPolicy6::NoFiltering,
                    None,
                ),
            };

        ctx.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
            asn: rq.asn,
            group: rq.group.clone(),
            name: rq.name.clone(),
            host: rq.host,
            parameters: BgpNeighborParameters {
                remote_asn: rq.parameters.remote_asn,
                min_ttl: rq.parameters.min_ttl,
                hold_time: rq.parameters.hold_time,
                idle_hold_time: rq.parameters.idle_hold_time,
                delay_open: rq.parameters.delay_open,
                connect_retry: rq.parameters.connect_retry,
                keepalive: rq.parameters.keepalive,
                resolution: rq.parameters.resolution,
                passive: rq.parameters.passive,
                md5_auth_key: rq.parameters.md5_auth_key,
                multi_exit_discriminator: rq
                    .parameters
                    .multi_exit_discriminator,
                communities: rq.parameters.communities,
                local_pref: rq.parameters.local_pref,
                enforce_first_as: rq.parameters.enforce_first_as,
                allow_import4,
                allow_import6,
                allow_export4,
                allow_export6,
                ipv4_enabled: rq.parameters.ipv4_unicast.is_some(),
                ipv6_enabled: rq.parameters.ipv6_unicast.is_some(),
                nexthop4,
                nexthop6,
                vlan_id: rq.parameters.vlan_id,
            },
        })?;

        if start_session {
            start_bgp_session(&event_tx)?;
        }

        Ok(())
    }

    pub(crate) fn add_unnumbered_neighbor(
        ctx: Arc<HandlerContext>,
        rq: UnnumberedNeighbor,
        ensure: bool,
    ) -> Result<(), Error> {
        let log = &ctx.log;
        bgp_log!(log, info, "add unnumbered neighbor {}", rq.interface;
            "params" => format!("{rq:#?}")
        );

        // Validate that at least one AF is enabled
        rq.validate_address_families()
            .map_err(Error::InvalidRequest)?;

        let (event_tx, event_rx) = channel();
        let info = SessionInfo::from(&rq.parameters);

        // XXX: remove this when PeerConfig no longer requires a SocketAddr
        let placeholder_host = std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        );

        let start_session = if ensure {
            match get_router!(&ctx, rq.asn)?.ensure_unnumbered_session(
                rq.interface.clone(),
                rq.to_peer_config(placeholder_host),
                None,
                event_tx.clone(),
                event_rx,
                info,
                ctx.bgp.unnumbered_manager.clone(),
            )? {
                EnsureSessionResult::New(_) => true,
                EnsureSessionResult::Updated(_) => false,
            }
        } else {
            get_router!(&ctx, rq.asn)?.new_unnumbered_session(
                rq.interface.clone(),
                rq.to_peer_config(placeholder_host),
                None,
                event_tx.clone(),
                event_rx,
                info,
                ctx.bgp.unnumbered_manager.clone(),
            )?;
            true
        };

        // Extract per-AF policies and nexthop for database storage
        let (allow_import4, allow_export4, nexthop4) =
            match &rq.parameters.ipv4_unicast {
                Some(cfg) => (
                    cfg.import_policy.clone(),
                    cfg.export_policy.clone(),
                    cfg.nexthop,
                ),
                None => (
                    ImportExportPolicy4::NoFiltering,
                    ImportExportPolicy4::NoFiltering,
                    None,
                ),
            };

        let (allow_import6, allow_export6, nexthop6) =
            match &rq.parameters.ipv6_unicast {
                Some(cfg) => (
                    cfg.import_policy.clone(),
                    cfg.export_policy.clone(),
                    cfg.nexthop,
                ),
                None => (
                    ImportExportPolicy6::NoFiltering,
                    ImportExportPolicy6::NoFiltering,
                    None,
                ),
            };

        ctx.db
            .add_unnumbered_bgp_neighbor(rdb::BgpUnnumberedNeighborInfo {
                asn: rq.asn,
                name: rq.name.clone(),
                group: rq.group.clone(),
                interface: rq.interface.clone(),
                router_lifetime: rq.act_as_a_default_ipv6_router,
                parameters: BgpNeighborParameters {
                    remote_asn: rq.parameters.remote_asn,
                    min_ttl: rq.parameters.min_ttl,
                    hold_time: rq.parameters.hold_time,
                    idle_hold_time: rq.parameters.idle_hold_time,
                    delay_open: rq.parameters.delay_open,
                    connect_retry: rq.parameters.connect_retry,
                    keepalive: rq.parameters.keepalive,
                    resolution: rq.parameters.resolution,
                    passive: rq.parameters.passive,
                    md5_auth_key: rq.parameters.md5_auth_key.clone(),
                    multi_exit_discriminator: rq
                        .parameters
                        .multi_exit_discriminator,
                    communities: rq.parameters.communities.clone(),
                    local_pref: rq.parameters.local_pref,
                    enforce_first_as: rq.parameters.enforce_first_as,
                    allow_import4,
                    allow_import6,
                    allow_export4,
                    allow_export6,
                    ipv4_enabled: rq.parameters.ipv4_unicast.is_some(),
                    ipv6_enabled: rq.parameters.ipv6_unicast.is_some(),
                    nexthop4,
                    nexthop6,
                    vlan_id: rq.parameters.vlan_id,
                },
            })?;

        // Register interface for NDP peer discovery (NDP-only, no session creation)
        ctx.bgp
            .unnumbered_manager
            .add_interface(&rq.interface, rq.act_as_a_default_ipv6_router)?;

        if start_session {
            start_bgp_session(&event_tx)?;
        }

        Ok(())
    }

    /// Central session reset logic - operates directly on a session.
    /// Sends the appropriate FSM events based on the reset operation type.
    fn reset_session(
        session: &Arc<SessionRunner<BgpConnectionTcp>>,
        op: NeighborResetOp,
    ) -> Result<(), Error> {
        match op {
            NeighborResetOp::Hard => {
                session
                    .event_tx
                    .send(FsmEvent::Admin(AdminEvent::Reset))
                    .map_err(|e| {
                        Error::InternalCommunication(format!(
                            "failed to reset bgp session {e}",
                        ))
                    })?;
            }
            NeighborResetOp::SoftInbound(afi) => {
                // Send the request to the FSM; it will handle checking capabilities
                // and which AFs are negotiated. None means all negotiated AFs.
                match afi {
                    Some(af) => {
                        session
                            .event_tx
                            .send(FsmEvent::Admin(AdminEvent::SendRouteRefresh(af)))
                            .map_err(|e| {
                                Error::InternalCommunication(format!(
                                    "failed to generate route refresh for {af}: {e}"
                                ))
                            })?;
                    }
                    None => {
                        // Send for both AFs; FSM will handle which are actually negotiated
                        session
                            .event_tx
                            .send(FsmEvent::Admin(
                                AdminEvent::SendRouteRefresh(Afi::Ipv4),
                            ))
                            .ok();
                        session
                            .event_tx
                            .send(FsmEvent::Admin(
                                AdminEvent::SendRouteRefresh(Afi::Ipv6),
                            ))
                            .ok();
                    }
                }
            }
            NeighborResetOp::SoftOutbound(afi) => {
                // Send the request to the FSM; it will handle which AFs are negotiated.
                // None means all negotiated AFs.
                match afi {
                    Some(af) => {
                        session
                            .event_tx
                            .send(FsmEvent::Admin(AdminEvent::ReAdvertiseRoutes(af)))
                            .map_err(|e| {
                                Error::InternalCommunication(format!(
                                    "failed to trigger outbound update for {af}: {e}"
                                ))
                            })?;
                    }
                    None => {
                        // Send for both AFs; FSM will handle which are actually negotiated
                        session
                            .event_tx
                            .send(FsmEvent::Admin(
                                AdminEvent::ReAdvertiseRoutes(Afi::Ipv4),
                            ))
                            .ok();
                        session
                            .event_tx
                            .send(FsmEvent::Admin(
                                AdminEvent::ReAdvertiseRoutes(Afi::Ipv6),
                            ))
                            .ok();
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn reset_neighbor(
        ctx: Arc<HandlerContext>,
        rq: NeighborResetRequest,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        bgp_log!(ctx.log, info, "clear {rq}");

        let session = get_router!(ctx, rq.asn)?
            .get_session(rq.addr)
            .ok_or(Error::NotFound("session for bgp peer not found".into()))?;

        reset_session(&session, rq.op)?;
        Ok(HttpResponseUpdatedNoContent())
    }

    pub(crate) async fn reset_unnumbered_neighbor(
        ctx: Arc<HandlerContext>,
        asn: u32,
        interface: &str,
        op: NeighborResetOp,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        bgp_log!(ctx.log, info, "clear unnumbered neighbor {interface}, asn {asn}";
            "op" => format!("{op:?}")
        );

        let session = ctx
            .bgp
            .unnumbered_manager
            .get_neighbor_session(asn, interface)?
            .ok_or(Error::NotFound(
                "session for unnumbered neighbor not found".into(),
            ))?;

        reset_session(&session, op)?;
        Ok(HttpResponseUpdatedNoContent())
    }

    pub(crate) fn add_router(
        ctx: Arc<HandlerContext>,
        rq: bgp::params::Router,
        routers: &mut BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>,
    ) -> Result<HttpResponseUpdatedNoContent, Error> {
        let cfg = RouterConfig {
            asn: Asn::FourOctet(rq.asn),
            id: rq.id,
        };

        let db = ctx.db.clone();

        let router = Arc::new(Router::<BgpConnectionTcp>::new(
            cfg,
            ctx.log.clone(),
            db.clone(),
            ctx.bgp.peer_to_session.clone(),
        ));

        router.run();

        routers.insert(rq.asn, router);
        db.add_bgp_router(
            rq.asn,
            BgpRouterInfo {
                id: rq.id,
                listen: rq.listen.clone(),
                graceful_shutdown: rq.graceful_shutdown,
            },
        )?;

        Ok(HttpResponseUpdatedNoContent())
    }

    fn start_bgp_session<Cnx: BgpConnection>(
        event_tx: &Sender<FsmEvent<Cnx>>,
    ) -> Result<(), Error> {
        event_tx
            .send(FsmEvent::Admin(AdminEvent::ManualStart))
            .map_err(|e| {
                Error::InternalCommunication(format!(
                    "failed to start bgp session {e}",
                ))
            })
    }

    pub async fn load_policy(
        ctx: &Arc<HandlerContext>,
        asn: u32,
        policy: PolicySource,
        overwrite: bool,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        match lock!(ctx.bgp.router).get(&asn) {
            None => {
                return Err(HttpError::for_not_found(
                    None,
                    String::from("ASN not found"),
                ));
            }
            Some(rtr) => {
                let load_result = match &policy {
                    PolicySource::Checker(code) => {
                        rtr.policy.load_checker(code, overwrite)
                    }
                    PolicySource::Shaper(code) => {
                        rtr.policy.load_shaper(code, overwrite)
                    }
                };
                match load_result {
                    Err(LoadPolicyError::Compilation(e)) => {
                        // The program failed to compile, return a bad request error
                        // with the error string from the compiler.
                        return Err(HttpError::for_bad_request(
                            None,
                            e.to_string(),
                        ));
                    }
                    Err(LoadPolicyError::Conflict) => {
                        return Err(HttpError::for_client_error_with_status(
                            Some("policy already loaded".to_string()),
                            ClientErrorStatusCode::CONFLICT,
                        ));
                    }
                    Ok(previous) => match &policy {
                        PolicySource::Checker(_) => {
                            rtr.send_admin_event(AdminEvent::CheckerChanged(
                                previous,
                            ))
                            .map_err(|e| {
                                HttpError::for_internal_error(format!(
                                    "send event: {e}"
                                ))
                            })?;
                        }
                        PolicySource::Shaper(_) => {
                            rtr.send_admin_event(AdminEvent::ShaperChanged(
                                previous,
                            ))
                            .map_err(|e| {
                                HttpError::for_internal_error(format!(
                                    "send event: {e}"
                                ))
                            })?;
                        }
                    },
                }
            }
        }
        Ok(HttpResponseUpdatedNoContent())
    }

    pub async fn unload_policy(
        ctx: &Arc<HandlerContext>,
        asn: u32,
        policy: PolicyKind,
    ) -> Result<HttpResponseDeleted, HttpError> {
        match lock!(ctx.bgp.router).get(&asn) {
            None => {
                return Err(HttpError::for_not_found(
                    None,
                    String::from("ASN not found"),
                ));
            }
            Some(rtr) => {
                let unload_result = match policy {
                    PolicyKind::Checker => rtr.policy.unload_checker(),
                    PolicyKind::Shaper => rtr.policy.unload_shaper(),
                };
                match unload_result {
                    Err(UnloadPolicyError::NotFound) => {
                        return Err(HttpError::for_not_found(
                            None,
                            "no policy loaded".to_string(),
                        ));
                    }
                    Ok(previous) => {
                        rtr.send_admin_event(AdminEvent::ShaperChanged(Some(
                            previous,
                        )))
                        .map_err(|e| {
                            HttpError::for_internal_error(format!(
                                "send event: {e}"
                            ))
                        })?;
                    }
                }
            }
        }
        Ok(HttpResponseDeleted())
    }

    /// Calculate exported routes for a single session.
    /// Returns None if the peer is not Established or has no routes to export.
    pub(crate) fn get_exported<Cnx: BgpConnection>(
        session: &SessionRunner<Cnx>,
        orig4: &[Prefix],
        orig6: &[Prefix],
        process_ipv4: bool,
        process_ipv6: bool,
    ) -> Option<(PeerId, Vec<Prefix>)> {
        // Only process Established peers
        if session.state() != FsmStateKind::Established {
            return None;
        }

        // Use PeerId as the key (supports both numbered and unnumbered peers)
        let peer_key = session.neighbor.peer.clone();

        // Get the primary connection to check negotiated capabilities
        let primary = session.primary_connection()?;

        // Extract negotiated AFI/SAFI states from the connection
        let (ipv4_negotiated, ipv6_negotiated) = match primary {
            ConnectionKind::Full(ref peer_conn) => (
                peer_conn.ipv4_unicast.negotiated(),
                peer_conn.ipv6_unicast.negotiated(),
            ),
            ConnectionKind::Partial(_) => return None,
        };

        // Get session configuration for export policies
        let session_info = lock!(session.session);
        let mut peer_exported_routes: Vec<Prefix> = Vec::new();

        // Process IPv4 routes if requested and negotiated
        if process_ipv4
            && ipv4_negotiated
            && let Some(ref ipv4_config) = session_info.ipv4_unicast
        {
            let mut v4_routes: Vec<Prefix> = orig4.to_vec();

            // Apply export policy
            match &ipv4_config.export_policy {
                ImportExportPolicy4::NoFiltering => {
                    peer_exported_routes.extend(v4_routes);
                }
                ImportExportPolicy4::Allow(allowed) => {
                    v4_routes.retain(|p| {
                        if let Prefix::V4(p4) = p {
                            allowed.contains(p4)
                        } else {
                            false
                        }
                    });
                    peer_exported_routes.extend(v4_routes);
                }
            }
        }

        // Process IPv6 routes if requested and negotiated
        if process_ipv6
            && ipv6_negotiated
            && let Some(ref ipv6_config) = session_info.ipv6_unicast
        {
            let mut v6_routes: Vec<Prefix> = orig6.to_vec();

            // Apply export policy
            match &ipv6_config.export_policy {
                ImportExportPolicy6::NoFiltering => {
                    peer_exported_routes.extend(v6_routes);
                }
                ImportExportPolicy6::Allow(allowed) => {
                    v6_routes.retain(|p| {
                        if let Prefix::V6(p6) = p {
                            allowed.contains(p6)
                        } else {
                            false
                        }
                    });
                    peer_exported_routes.extend(v6_routes);
                }
            }
        }

        // Only return if we have exported routes
        if peer_exported_routes.is_empty() {
            return None;
        }

        // Stable output order for clients
        peer_exported_routes.sort();
        Some((peer_key, peer_exported_routes))
    }
}

#[cfg(test)]
mod tests {
    use super::do_bgp_apply;
    use crate::{
        admin::HandlerContext, bfd_admin::BfdContext, bgp_admin::BgpContext,
    };
    use bgp::params::{ApplyRequestV1, BgpPeerConfigV1, BgpPeerParametersV1};
    use mg_common::stats::MgLowerStats;
    use rdb::test::get_test_db;
    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    use std::net::Ipv6Addr;
    use std::{
        collections::{BTreeMap, HashMap},
        env::temp_dir,
        fs::{create_dir_all, remove_dir_all},
        net::SocketAddr,
        sync::{Arc, Mutex},
    };

    #[tokio::test]
    async fn apply_remove_entire_group() {
        let tmpdir = temp_dir();
        let tmpdir = format!(
            "{}/maghemite-test/apply_remove_entire_group",
            tmpdir.to_str().unwrap()
        );
        if std::fs::exists(&tmpdir).unwrap() {
            remove_dir_all(&tmpdir).unwrap();
        }
        create_dir_all(&tmpdir).unwrap();
        println!("tmpdir is {tmpdir}");
        let log =
            mg_common::log::init_file_logger("apply_remove_entire_group.log");

        let db = get_test_db("apply_remove_entire_group", log.clone()).unwrap();
        let ctx = Arc::new(HandlerContext {
            #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
            tep: Ipv6Addr::UNSPECIFIED,
            bgp: BgpContext::new(
                Arc::new(Mutex::new(BTreeMap::new())),
                log.clone(),
            ),
            bfd: BfdContext::new(log.clone()),
            log: log.clone(),
            db: (*db).clone(),
            mg_lower_stats: Arc::new(MgLowerStats::default()),
            stats_server_running: Mutex::new(false),
            oximeter_port: 0,
        });

        let mut peers = HashMap::new();
        peers.insert(
            String::from("qsfp0"),
            vec![BgpPeerConfigV1 {
                host: SocketAddr::new("203.0.113.1".parse().unwrap(), 179),
                name: String::from("bob"),
                parameters: BgpPeerParametersV1 {
                    hold_time: 3,
                    idle_hold_time: 1,
                    delay_open: 1,
                    connect_retry: 1,
                    keepalive: 1,
                    resolution: 1,
                    passive: false,
                    remote_asn: None,
                    min_ttl: None,
                    md5_auth_key: None,
                    multi_exit_discriminator: None,
                    communities: Vec::default(),
                    local_pref: None,
                    enforce_first_as: false,
                    allow_import: rdb::ImportExportPolicyV1::NoFiltering,
                    allow_export: rdb::ImportExportPolicyV1::NoFiltering,
                    vlan_id: None,
                },
            }],
        );
        peers.insert(
            String::from("qsfp1"),
            vec![BgpPeerConfigV1 {
                host: SocketAddr::new("203.0.113.2".parse().unwrap(), 179),
                name: String::from("alice"),
                parameters: BgpPeerParametersV1 {
                    hold_time: 3,
                    idle_hold_time: 1,
                    delay_open: 1,
                    connect_retry: 1,
                    keepalive: 1,
                    resolution: 1,
                    passive: false,
                    remote_asn: None,
                    min_ttl: None,
                    md5_auth_key: None,
                    multi_exit_discriminator: None,
                    communities: Vec::default(),
                    local_pref: None,
                    enforce_first_as: false,
                    allow_import: rdb::ImportExportPolicyV1::NoFiltering,
                    allow_export: rdb::ImportExportPolicyV1::NoFiltering,
                    vlan_id: None,
                },
            }],
        );

        let mut req = ApplyRequestV1 {
            asn: 47,
            originate: Vec::default(),
            checker: None,
            shaper: None,
            peers,
        };

        do_bgp_apply(&ctx, req.clone().into())
            .await
            .expect("bgp apply request");

        assert_eq!(
            ctx.db.get_bgp_neighbors().expect("get bgp neighbors").len(),
            2,
        );

        req.peers.remove("qsfp0");

        do_bgp_apply(&ctx, req.clone().into())
            .await
            .expect("bgp apply request");

        assert_eq!(
            ctx.db.get_bgp_neighbors().expect("get bgp neighbors").len(),
            1,
        );
    }
}
