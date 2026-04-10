// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{bfd_admin, bgp_admin, rib_admin, static_admin};
use bfd_admin::BfdContext;
use bgp::params::*;
use bgp_admin::BgpContext;
use dropshot::{
    ApiDescription, ConfigDropshot, HttpError, HttpResponseDeleted,
    HttpResponseOk, HttpResponseUpdatedNoContent, Path, Query, RequestContext,
    TypedBody,
};
use mg_api::{MgAdminApi, mg_admin_api_mod};
use mg_common::stats::MgLowerStats;
use mg_types::bfd::{BfdPeerInfo, DeleteBfdPeerPathParams};
use mg_types::bgp::{
    AsnSelector, ExportedSelector, FsmHistoryRequest, FsmHistoryResponse,
    MessageHistoryRequest, MessageHistoryResponse, NeighborResetRequest,
    NeighborSelector, UnnumberedNeighborResetRequest,
    UnnumberedNeighborSelector,
};
use mg_types::ndp::{NdpInterface, NdpInterfaceSelector, NdpManagerState};
use mg_types::rib::{
    BestpathFanoutRequest, BestpathFanoutResponse, GetRibResult, Rib, RibQuery,
};
use mg_types::static_routes::{
    AddStaticRoute4Request, AddStaticRoute6Request, DeleteStaticRoute4Request,
    DeleteStaticRoute6Request,
};
use mg_types::switch::SwitchIdentifiers;
use mg_types_versions::{v1, v2, v5};
use rdb::{BfdPeerConfig, Db, PeerId, Prefix};
use slog::{Logger, error, info, o};
use std::collections::HashMap;
#[cfg(all(feature = "mg-lower", target_os = "illumos"))]
use std::net::Ipv6Addr;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

const UNIT_API_SERVER: &str = "api_server";

pub struct HandlerContext {
    #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
    pub tep: Ipv6Addr, // tunnel endpoint address
    pub bgp: BgpContext,
    pub bfd: BfdContext,
    pub log: Logger,
    pub db: Db,
    pub mg_lower_stats: Arc<MgLowerStats>,
    pub stats_server_running: Mutex<bool>,
    pub oximeter_port: u16,
}

pub fn start_server(
    log: Logger,
    addr: IpAddr,
    port: u16,
    context: Arc<HandlerContext>,
) -> Result<JoinHandle<()>, String> {
    let sa = SocketAddr::new(addr, port);
    let ds_config = ConfigDropshot {
        bind_address: sa,
        default_request_body_max_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    };

    let ds_log = log.new(o!(
        "component" => crate::COMPONENT_MGD,
        "module" => crate::MOD_ADMIN,
        "unit" => UNIT_API_SERVER
    ));

    let api = api_description();

    let server = dropshot::ServerBuilder::new(api, context, ds_log)
        .config(ds_config)
        .version_policy(dropshot::VersionPolicy::Dynamic(Box::new(
            dropshot::ClientSpecifiesVersionInHeader::new(
                omicron_common::api::VERSION_HEADER,
                mg_api::latest_version(),
            ),
        )));

    info!(log, "listening on {sa}");

    Ok(tokio::spawn(async move {
        match server.start() {
            Ok(server) => {
                info!(log, "admin: server started");
                match server.await {
                    Ok(()) => info!(log, "admin: server exited"),
                    Err(e) => error!(log, "admin: server error {e:?}";
                        "error" => format!("{e}")
                    ),
                }
            }
            Err(e) => error!(log, "admin: server start error {e:?}";
                        "error" => format!("{e}")
            ),
        }
    }))
}

pub enum MgAdminApiImpl {}

impl MgAdminApi for MgAdminApiImpl {
    type Context = Arc<HandlerContext>;

    async fn get_bfd_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<BfdPeerInfo>>, HttpError> {
        bfd_admin::get_bfd_peers(ctx).await
    }

    async fn add_bfd_peer(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<BfdPeerConfig>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bfd_admin::add_bfd_peer(ctx, request).await
    }

    async fn remove_bfd_peer(
        ctx: RequestContext<Self::Context>,
        params: Path<DeleteBfdPeerPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bfd_admin::remove_bfd_peer(ctx, params).await
    }

    async fn read_routers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<Router>>, HttpError> {
        bgp_admin::read_routers(ctx).await
    }

    async fn create_router(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_router(ctx, request).await
    }

    async fn read_router(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Router>, HttpError> {
        bgp_admin::read_router(ctx, request).await
    }

    async fn update_router(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_router(ctx, request).await
    }

    async fn delete_router(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::delete_router(ctx, request).await
    }

    // Neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - Neighbor with DSCP

    async fn create_neighbor(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_neighbor_v4(ctx, request).await
    }

    async fn read_neighbor(
        ctx: RequestContext<Self::Context>,
        path: Path<NeighborSelector>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError> {
        bgp_admin::read_neighbor_v4(ctx, path).await
    }

    async fn read_neighbors(
        ctx: RequestContext<Self::Context>,
        path: Path<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError> {
        bgp_admin::read_neighbors_v4(ctx, path).await
    }

    async fn update_neighbor(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_neighbor_v4(ctx, request).await
    }

    async fn delete_neighbor(
        ctx: RequestContext<Self::Context>,
        path: Path<NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_neighbor_v4(ctx, path).await
    }

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - provided methods
    // V4 (VERSION_MP_BGP..VERSION_UNNUMBERED) - provided methods

    // V1 (..VERSION_MP_BGP)

    async fn create_neighbor_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_neighbor_v1(ctx, request).await
    }

    async fn read_neighbor_v1(
        ctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV1>, HttpError> {
        bgp_admin::read_neighbor_v1(ctx, request).await
    }

    async fn read_neighbors_v1(
        ctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV1>>, HttpError> {
        bgp_admin::read_neighbors_v1(ctx, request).await
    }

    async fn update_neighbor_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_neighbor_v1(ctx, request).await
    }

    // delete_neighbor_v1 and clear_neighbor_v1 are provided methods.

    async fn clear_neighbor(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::clear_neighbor(ctx, request).await
    }

    // Unnumbered neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - UnnumberedNeighbor with DSCP

    async fn read_unnumbered_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<UnnumberedNeighbor>>, HttpError> {
        bgp_admin::read_unnumbered_neighbors_v2(rqctx, request).await
    }

    async fn create_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_unnumbered_neighbor_v2(rqctx, request).await
    }

    async fn read_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<UnnumberedNeighbor>, HttpError> {
        bgp_admin::read_unnumbered_neighbor_v2(rqctx, request).await
    }

    async fn update_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_unnumbered_neighbor_v2(rqctx, request).await
    }

    async fn delete_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_unnumbered_neighbor_v2(rqctx, request).await
    }

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - provided methods

    async fn clear_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::clear_unnumbered_neighbor(rqctx, request).await
    }

    // IPv4 origin ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    async fn create_origin4(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_origin4(ctx, request).await
    }

    async fn read_origin4(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Origin4>, HttpError> {
        bgp_admin::read_origin4(ctx, request).await
    }

    async fn update_origin4(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_origin4(ctx, request).await
    }

    async fn delete_origin4(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_origin4(ctx, request).await
    }

    async fn create_origin6(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_origin6(ctx, request).await
    }

    async fn read_origin6(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Origin6>, HttpError> {
        bgp_admin::read_origin6(ctx, request).await
    }

    async fn update_origin6(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_origin6(ctx, request).await
    }

    async fn delete_origin6(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_origin6(ctx, request).await
    }

    async fn get_exported(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, Vec<Prefix>>>, HttpError> {
        bgp_admin::get_exported(ctx, request).await
    }

    async fn get_exported_v5(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<PeerId, Vec<Prefix>>>, HttpError> {
        bgp_admin::get_exported_v5(ctx, request).await
    }

    async fn get_exported_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError> {
        bgp_admin::get_exported_v1(ctx, request).await
    }

    // RIB imported/selected ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - RibQuery with prefix filter
    async fn get_rib_imported(
        ctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError> {
        rib_admin::get_rib_imported(ctx, request).await
    }

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING)
    async fn get_rib_imported_v5(
        ctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v5::rib::Rib>, HttpError> {
        rib_admin::get_rib_imported_v5(ctx, request).await
    }

    async fn get_rib_imported_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError> {
        rib_admin::get_rib_imported_v2(ctx, request).await
    }

    async fn get_imported_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError> {
        bgp_admin::get_imported_v1(ctx, request).await
    }

    // Latest (VERSION_SPRING_CLEANING..) - RibQuery with prefix filter
    async fn get_rib_selected(
        ctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError> {
        rib_admin::get_rib_selected(ctx, request).await
    }

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING)
    async fn get_rib_selected_v5(
        ctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v5::rib::Rib>, HttpError> {
        rib_admin::get_rib_selected_v5(ctx, request).await
    }

    async fn get_rib_selected_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError> {
        rib_admin::get_rib_selected_v2(ctx, request).await
    }

    async fn get_selected_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError> {
        bgp_admin::get_selected_v1(ctx, request).await
    }

    // Neighbors status ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - PeerInfo with per-AFI counters
    async fn get_neighbors(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError> {
        bgp_admin::get_neighbors_v5(ctx, request).await
    }

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING)
    async fn get_neighbors_v5(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, PeerInfoV3>>, HttpError> {
        bgp_admin::get_neighbors(ctx, request).await
    }

    async fn get_neighbors_v4(
        ctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV3>>, HttpError> {
        bgp_admin::get_neighbors_v4(ctx, request).await
    }

    async fn get_neighbors_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError> {
        bgp_admin::get_neighbors_v2(ctx, request).await
    }

    async fn get_neighbors_v1(
        ctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError> {
        bgp_admin::get_neighbors_v1(ctx, request).await
    }

    // Apply ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - ApplyRequest with DSCP
    async fn bgp_apply(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::bgp_apply(ctx, request).await
    }

    // bgp_apply_v4 and bgp_apply_v1 are provided methods.

    // Message history ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - buffer selection, flat entries
    async fn message_history(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError> {
        bgp_admin::message_history_v4(ctx, request).await
    }

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING)
    async fn message_history_v5(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v5::bgp::MessageHistoryResponse>, HttpError>
    {
        bgp_admin::message_history_v3(ctx, request).await
    }

    async fn message_history_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v2::bgp::MessageHistoryResponse>, HttpError>
    {
        bgp_admin::message_history_v2(ctx, request).await
    }

    async fn message_history_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v1::bgp::MessageHistoryResponse>, HttpError>
    {
        bgp_admin::message_history_v1(ctx, request).await
    }

    async fn fsm_history(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<FsmHistoryResponse>, HttpError> {
        bgp_admin::fsm_history(ctx, request).await
    }

    async fn fsm_history_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<v2::bgp::FsmHistoryResponse>, HttpError> {
        bgp_admin::fsm_history_v2(ctx, request).await
    }

    async fn create_checker(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_checker(ctx, request).await
    }

    async fn read_checker(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<CheckerSource>, HttpError> {
        bgp_admin::read_checker(ctx, request).await
    }

    async fn update_checker(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_checker(ctx, request).await
    }

    async fn delete_checker(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_checker(ctx, request).await
    }

    async fn create_shaper(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_shaper(ctx, request).await
    }

    async fn read_shaper(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<ShaperSource>, HttpError> {
        bgp_admin::read_shaper(ctx, request).await
    }

    async fn update_shaper(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_shaper(ctx, request).await
    }

    async fn delete_shaper(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_shaper(ctx, request).await
    }

    // read_bestpath_fanout_v1 and update_bestpath_fanout_v1 are provided
    // methods.

    async fn read_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
        rib_admin::read_bestpath_fanout(rqctx).await
    }

    async fn update_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        rib_admin::update_bestpath_fanout(rqctx, request).await
    }

    // Static routes ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - IpAddr nexthop + interface
    async fn static_add_v4_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        static_admin::static_add_v4_route_v2(ctx, request).await
    }

    async fn static_remove_v4_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        static_admin::static_remove_v4_route_v2(ctx, request).await
    }

    async fn static_list_v4_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<GetRibResult>, HttpError> {
        static_admin::static_list_v4_routes(ctx).await
    }

    async fn static_add_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        static_admin::static_add_v6_route_v2(ctx, request).await
    }

    async fn static_remove_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        static_admin::static_remove_v6_route_v2(ctx, request).await
    }

    async fn static_list_v6_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<GetRibResult>, HttpError> {
        static_admin::static_list_v6_routes(ctx).await
    }

    // V1 static routes (..VERSION_SPRING_CLEANING) - typed nexthop
    async fn static_add_v4_route_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v1::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        static_admin::static_add_v4_route(ctx, request).await
    }

    async fn static_remove_v4_route_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v1::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        static_admin::static_remove_v4_route(ctx, request).await
    }

    // static_list_v4_routes_v1 is a provided method.

    async fn static_add_v6_route_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::static_routes::AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        static_admin::static_add_v6_route(ctx, request).await
    }

    async fn static_remove_v6_route_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::static_routes::DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        static_admin::static_remove_v6_route(ctx, request).await
    }

    // static_list_v6_routes_v1 is a provided method.

    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError> {
        static_admin::switch_identifiers(ctx).await
    }

    async fn get_ndp_manager_state(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<NdpManagerState>, HttpError> {
        bgp_admin::get_ndp_manager_state(ctx, request).await
    }

    async fn get_ndp_interfaces(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NdpInterface>>, HttpError> {
        bgp_admin::get_ndp_interfaces(ctx, request).await
    }

    async fn get_ndp_interface_detail(
        ctx: RequestContext<Self::Context>,
        request: Query<NdpInterfaceSelector>,
    ) -> Result<HttpResponseOk<NdpInterface>, HttpError> {
        bgp_admin::get_ndp_interface_detail(ctx, request).await
    }
}

pub fn api_description() -> ApiDescription<Arc<HandlerContext>> {
    mg_admin_api_mod::api_description::<MgAdminApiImpl>().unwrap()
}
