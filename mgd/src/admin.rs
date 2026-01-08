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
use mg_api::*;
use mg_common::stats::MgLowerStats;
use rdb::{BfdPeerConfig, Db, Prefix};
use slog::{Logger, error, info, o};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

const UNIT_API_SERVER: &str = "api_server";

pub struct HandlerContext {
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

    async fn read_neighbors(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV1>>, HttpError> {
        bgp_admin::read_neighbors(ctx, request).await
    }

    async fn create_neighbor(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_neighbor(ctx, request).await
    }

    async fn read_neighbor(
        ctx: RequestContext<Self::Context>,
        request: Query<NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV1>, HttpError> {
        bgp_admin::read_neighbor(ctx, request).await
    }

    async fn update_neighbor(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_neighbor(ctx, request).await
    }

    async fn delete_neighbor(
        ctx: RequestContext<Self::Context>,
        request: Query<NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_neighbor(ctx, request).await
    }

    async fn read_neighbors_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError> {
        bgp_admin::read_neighbors_v2(ctx, request).await
    }

    async fn create_neighbor_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::create_neighbor_v2(ctx, request).await
    }

    async fn read_neighbor_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<NeighborSelector>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError> {
        bgp_admin::read_neighbor_v2(ctx, request).await
    }

    async fn update_neighbor_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_neighbor_v2(ctx, request).await
    }

    async fn delete_neighbor_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        bgp_admin::delete_neighbor_v2(ctx, request).await
    }

    async fn clear_neighbor(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborResetRequestV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::clear_neighbor(ctx, request).await
    }

    async fn clear_neighbor_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::clear_neighbor_v2(ctx, request).await
    }

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
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError> {
        bgp_admin::get_exported(ctx, request).await
    }

    async fn get_imported(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<Rib>, HttpError> {
        bgp_admin::get_imported(ctx, request).await
    }

    async fn get_selected(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<Rib>, HttpError> {
        bgp_admin::get_selected(ctx, request).await
    }

    async fn get_rib_imported(
        ctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError> {
        rib_admin::get_rib_imported(ctx, request).await
    }

    async fn get_rib_selected(
        ctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError> {
        rib_admin::get_rib_selected(ctx, request).await
    }

    async fn get_neighbors(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError> {
        bgp_admin::get_neighbors(ctx, request).await
    }

    async fn get_neighbors_v2(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError> {
        bgp_admin::get_neighbors_v2(ctx, request).await
    }

    async fn get_neighbors_v3(
        ctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfo>>, HttpError> {
        bgp_admin::get_neighbors_v3(ctx, request).await
    }

    async fn bgp_apply(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequestV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::bgp_apply(ctx, request).await
    }

    async fn bgp_apply_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::bgp_apply_v2(ctx, request).await
    }

    async fn message_history(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequestV1>,
    ) -> Result<HttpResponseOk<MessageHistoryResponseV1>, HttpError> {
        bgp_admin::message_history(ctx, request).await
    }

    async fn message_history_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError> {
        bgp_admin::message_history_v2(ctx, request).await
    }

    async fn fsm_history(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<FsmHistoryResponse>, HttpError> {
        bgp_admin::fsm_history(ctx, request).await
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

    async fn read_bestpath_fanout(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
        bgp_admin::read_bestpath_fanout(ctx).await
    }

    async fn update_bestpath_fanout(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        bgp_admin::update_bestpath_fanout(ctx, request).await
    }

    async fn read_rib_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
        rib_admin::read_rib_bestpath_fanout(rqctx).await
    }

    async fn update_rib_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        rib_admin::update_rib_bestpath_fanout(rqctx, request).await
    }

    async fn static_add_v4_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        static_admin::static_add_v4_route(ctx, request).await
    }

    async fn static_remove_v4_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        static_admin::static_remove_v4_route(ctx, request).await
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
        static_admin::static_add_v6_route(ctx, request).await
    }

    async fn static_remove_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        static_admin::static_remove_v6_route(ctx, request).await
    }

    async fn static_list_v6_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<GetRibResult>, HttpError> {
        static_admin::static_list_v6_routes(ctx).await
    }

    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError> {
        static_admin::switch_identifiers(ctx).await
    }
}

pub fn api_description() -> ApiDescription<Arc<HandlerContext>> {
    mg_admin_api_mod::api_description::<MgAdminApiImpl>().unwrap()
}
