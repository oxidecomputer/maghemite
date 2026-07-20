// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use oxnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use mg_api_types_versions::{latest, v1, v2, v4, v5, v8, v10};

api_versions!([
    // WHEN CHANGING THE API (part 1 of 2):
    //
    // +- Pick a new semver and define it in the list below.  The list MUST
    // |  remain sorted, which generally means that your version should go at
    // |  the very top.
    // |
    // |  Duplicate this line, uncomment the *second* copy, update that copy for
    // |  your new API version, and leave the first copy commented out as an
    // |  example for the next person.
    // v
    // (next_int, IDENT),
    (12, MULTICAST_SUPPORT),
    (11, PREFIX_TO_OXNET),
    (10, V4_OVER_V6_STATIC_ROUTES),
    (9, ENDPOINT_RENAME),
    (8, BGP_SRC_ADDR),
    (7, OPERATION_ID_CLEANUP),
    (6, RIB_EXPORTED_STRING_KEY),
    (5, UNNUMBERED),
    (4, MP_BGP),
    (3, SWITCH_IDENTIFIERS),
    (2, IPV6_BASIC),
    (1, INITIAL),
]);

// WHEN CHANGING THE API (part 2 of 2):
//
// The call to `api_versions!` above defines constants of type
// `semver::Version` that you can use in your Dropshot API definition to specify
// the version when a particular endpoint was added or removed.  For example, if
// you used:
//
//     (1, INITIAL)
//
// Then you could use `VERSION_INITIAL` as the version in which endpoints were
// added or removed.

#[dropshot::api_description]
pub trait MgAdminApi {
    type Context;

    /// Get all the peers and their associated BFD state. Peers are identified by IP
    /// address.
    #[endpoint {
        method = GET,
        path = "/bfd/peers",
    }]
    async fn get_bfd_peers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::bfd::BfdPeerInfo>>, HttpError>;

    /// Add a new peer to the daemon. A session for the specified peer will start
    /// immediately.
    #[endpoint {
        method = PUT,
        path = "/bfd/peers",
    }]
    async fn add_bfd_peer(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bfd::BfdPeerConfig>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove the specified peer from the daemon. The associated peer session will
    /// be stopped immediately.
    #[endpoint {
        method = DELETE,
        path = "/bfd/peers/{addr}",
    }]
    async fn remove_bfd_peer(
        rqctx: RequestContext<Self::Context>,
        params: Path<latest::bfd::DeleteBfdPeerPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/routers",
    }]
    async fn read_routers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::bgp::config::Router>>, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/router",
    }]
    async fn create_router(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/router",
    }]
    async fn read_router(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::bgp::config::Router>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/router",
    }]
    async fn update_router(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/router",
    }]
    async fn delete_router(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // Neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest API

    #[endpoint {
        method = PUT,
        path = "/bgp/config/neighbor",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn create_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbor/{asn}/{peer}",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn read_neighbor(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseOk<latest::bgp::config::Neighbor>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbors/{asn}",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn read_neighbors(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<latest::bgp::config::Neighbor>>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/neighbor",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn update_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/neighbor/{asn}/{peer}",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn delete_neighbor(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V8 API (VERSION_BGP_SRC_ADDR..) - supports src_addr/src_port for
    // per-neighbor source address binding.

    #[endpoint {
        method = PUT,
        path = "/bgp/config/neighbor",
        operation_id = "create_neighbor",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn create_neighbor_v8(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_neighbor(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbor/{asn}/{peer}",
        operation_id = "read_neighbor",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn read_neighbor_v8(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseOk<v8::bgp::config::Neighbor>, HttpError> {
        Self::read_neighbor(rqctx, path)
            .await
            .map(|r| r.map(Into::into))
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbors/{asn}",
        operation_id = "read_neighbors",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn read_neighbors_v8(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<v8::bgp::config::Neighbor>>, HttpError> {
        Self::read_neighbors(rqctx, path)
            .await
            .map(|r| r.map(|v| v.into_iter().map(Into::into).collect()))
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/neighbor",
        operation_id = "update_neighbor",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn update_neighbor_v8(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_neighbor(rqctx, request.map(Into::into)).await
    }

    // V5 API (VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR) - supports both
    // numbered and unnumbered neighbors but lacks src_addr/src_port.

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbor/{asn}/{peer}",
        operation_id = "read_neighbor",
        versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR,
    }]
    async fn read_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<v5::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseOk<v4::bgp::config::Neighbor>, HttpError> {
        Self::read_neighbor_v8(rqctx, path)
            .await
            .map(|r| r.map(Into::into))
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbors/{asn}",
        operation_id = "read_neighbors",
        versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR,
    }]
    async fn read_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<v4::bgp::config::Neighbor>>, HttpError> {
        Self::read_neighbors_v8(rqctx, path)
            .await
            .map(|r| r.map(|v| v.into_iter().map(Into::into).collect()))
    }

    // V4 API - new Neighbor type with explicit per-AF configuration (numbered
    // peers only).

    #[endpoint {
        method = PUT,
        path = "/bgp/config/neighbor",
        operation_id = "create_neighbor",
        versions = VERSION_MP_BGP..VERSION_BGP_SRC_ADDR,
    }]
    async fn create_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v4::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_neighbor_v8(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbor",
        operation_id = "read_neighbor",
        versions = VERSION_MP_BGP..VERSION_UNNUMBERED,
    }]
    async fn read_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseOk<v4::bgp::config::Neighbor>, HttpError> {
        let rq = request.into_inner();
        Self::read_neighbor_v5(
            rqctx,
            v5::bgp::config::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbors",
        operation_id = "read_neighbors",
        versions = VERSION_MP_BGP..VERSION_UNNUMBERED,
    }]
    async fn read_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<v4::bgp::config::Neighbor>>, HttpError> {
        Self::read_neighbors_v5(rqctx, request.into_inner().into()).await
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/neighbor",
        operation_id = "update_neighbor",
        versions = VERSION_MP_BGP..VERSION_BGP_SRC_ADDR,
    }]
    async fn update_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v4::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_neighbor_v8(rqctx, request.map(Into::into)).await
    }

    // V1/V2 API - legacy Neighbor type with combined import/export policies.
    //
    // These four endpoints (create/read/read-all/update) are required methods
    // rather than provided defaults because there is no `From<v1::Neighbor>
    // for v4::Neighbor` (or vice-versa) that the trait can call: the v1
    // `Neighbor` carries a single `allow_import`/`allow_export` policy pair
    // (IPv4 implicit), whereas v4+ carries per-AF policies plus enable
    // flags. Constructing a v4 shape from v1 input requires the rdb-backed
    // defaults that only `Self::Context` can supply (see
    // `bgp_admin::helpers::add_neighbor_v1`); constructing v1 from v4
    // requires merging per-AF policies, which loses information when both
    // AFs are enabled. `delete_neighbor_v1` and `clear_neighbor_v1` can be
    // provided because their inputs project cleanly into v5/v4 shapes.

    #[endpoint {
        method = PUT,
        path = "/bgp/config/neighbor",
        operation_id = "create_neighbor",
        versions = ..VERSION_MP_BGP,
    }]
    async fn create_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbor",
        operation_id = "read_neighbor",
        versions = ..VERSION_MP_BGP,
    }]
    async fn read_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseOk<v1::bgp::config::Neighbor>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/neighbors",
        operation_id = "read_neighbors",
        versions = ..VERSION_MP_BGP,
    }]
    async fn read_neighbors_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<v1::bgp::config::Neighbor>>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/neighbor",
        operation_id = "update_neighbor",
        versions = ..VERSION_MP_BGP,
    }]
    async fn update_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/neighbor",
        operation_id = "delete_neighbor",
        versions = ..VERSION_UNNUMBERED,
    }]
    async fn delete_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let rq = request.into_inner();
        Self::delete_neighbor(
            rqctx,
            v5::bgp::config::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    // V4+ API clear neighbor with per-AF support
    #[endpoint {
        method = POST,
        path = "/bgp/clear/neighbor",
        versions = VERSION_MP_BGP..,
    }]
    async fn clear_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V1/V2 API clear neighbor (backwards compatibility w/ IPv4 only support)
    #[endpoint {
        method = POST,
        path = "/bgp/clear/neighbor",
        operation_id = "clear_neighbor",
        versions = ..VERSION_MP_BGP,
    }]
    async fn clear_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::clear_neighbor(rqctx, request.map(Into::into)).await
    }

    // Unnumbered neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest API

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbors",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn read_unnumbered_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<Vec<latest::bgp::config::UnnumberedNeighbor>>,
        HttpError,
    >;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn create_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn read_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::UnnumberedNeighborSelector>,
    ) -> Result<
        HttpResponseOk<latest::bgp::config::UnnumberedNeighbor>,
        HttpError,
    >;

    #[endpoint {
        method = POST,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn update_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn delete_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V8 API (VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET)

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbors",
        operation_id = "read_unnumbered_neighbors",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn read_unnumbered_neighbors_v8(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<Vec<v8::bgp::config::UnnumberedNeighbor>>,
        HttpError,
    > {
        Self::read_unnumbered_neighbors(rqctx, request)
            .await
            .map(|r| r.map(|v| v.into_iter().map(Into::into).collect()))
    }

    #[endpoint {
        method = PUT,
        path = "/bgp/config/unnumbered-neighbor",
        operation_id = "create_unnumbered_neighbor",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn create_unnumbered_neighbor_v8(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::bgp::config::UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_unnumbered_neighbor(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbor",
        operation_id = "read_unnumbered_neighbor",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn read_unnumbered_neighbor_v8(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<v8::bgp::config::UnnumberedNeighbor>, HttpError>
    {
        Self::read_unnumbered_neighbor(rqctx, request)
            .await
            .map(|r| r.map(Into::into))
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/unnumbered-neighbor",
        operation_id = "update_unnumbered_neighbor",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn update_unnumbered_neighbor_v8(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::bgp::config::UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_unnumbered_neighbor(rqctx, request.map(Into::into)).await
    }

    // V5 API (VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR) - unnumbered neighbors
    // without src_addr/src_port. Operation IDs match the latest endpoints so
    // a single client method covers all versions.

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbors",
        operation_id = "read_unnumbered_neighbors",
        versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR,
    }]
    async fn read_unnumbered_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<Vec<v5::bgp::config::UnnumberedNeighbor>>,
        HttpError,
    > {
        Self::read_unnumbered_neighbors_v8(rqctx, request)
            .await
            .map(|r| r.map(|v| v.into_iter().map(Into::into).collect()))
    }

    #[endpoint {
        method = PUT,
        path = "/bgp/config/unnumbered-neighbor",
        operation_id = "create_unnumbered_neighbor",
        versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR,
    }]
    async fn create_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::config::UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_unnumbered_neighbor_v8(rqctx, request.map(Into::into))
            .await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbor",
        operation_id = "read_unnumbered_neighbor",
        versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR,
    }]
    async fn read_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<v5::bgp::config::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<v5::bgp::config::UnnumberedNeighbor>, HttpError>
    {
        Self::read_unnumbered_neighbor_v8(rqctx, request)
            .await
            .map(|r| r.map(Into::into))
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/unnumbered-neighbor",
        operation_id = "update_unnumbered_neighbor",
        versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR,
    }]
    async fn update_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::config::UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_unnumbered_neighbor_v8(rqctx, request.map(Into::into))
            .await
    }

    #[endpoint {
        method = POST,
        path = "/bgp/clear/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn clear_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::UnnumberedNeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // IPv4 origin ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint {
        method = PUT,
        path = "/bgp/config/origin4",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn create_origin4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/origin4",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn read_origin4(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::bgp::config::Origin4>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/origin4",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn update_origin4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/origin4",
        versions = ..,
    }]
    async fn delete_origin4(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/origin4",
        operation_id = "create_origin4",
        versions = ..VERSION_PREFIX_TO_OXNET,
    }]
    async fn create_origin4_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_origin4(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/origin4",
        operation_id = "read_origin4",
        versions = ..VERSION_PREFIX_TO_OXNET,
    }]
    async fn read_origin4_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::bgp::config::Origin4>, HttpError> {
        Self::read_origin4(rqctx, request)
            .await
            .map(|r| r.map(Into::into))
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/origin4",
        operation_id = "update_origin4",
        versions = ..VERSION_PREFIX_TO_OXNET,
    }]
    async fn update_origin4_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_origin4(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = PUT,
        path = "/bgp/config/origin6",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn create_origin6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::history::Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/origin6",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn read_origin6(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::bgp::history::Origin6>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/origin6",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn update_origin6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::history::Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/origin6",
        versions = VERSION_IPV6_BASIC..,
    }]
    async fn delete_origin6(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/origin6",
        operation_id = "create_origin6",
        versions = VERSION_IPV6_BASIC..VERSION_PREFIX_TO_OXNET,
    }]
    async fn create_origin6_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::history::Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_origin6(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/origin6",
        operation_id = "read_origin6",
        versions = VERSION_IPV6_BASIC..VERSION_PREFIX_TO_OXNET,
    }]
    async fn read_origin6_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<v2::bgp::history::Origin6>, HttpError> {
        Self::read_origin6(rqctx, request)
            .await
            .map(|r| r.map(Into::into))
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/origin6",
        operation_id = "update_origin6",
        versions = VERSION_IPV6_BASIC..VERSION_PREFIX_TO_OXNET,
    }]
    async fn update_origin6_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::history::Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_origin6(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/status/exported",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn get_exported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::session::ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, Vec<IpNet>>>, HttpError>;

    // Fixed: uses String keys from PeerId Display (e.g. "192.0.2.1" or
    // "tfportqsfp0_0").
    #[endpoint {
        method = GET,
        path = "/bgp/status/exported",
        operation_id = "get_exported",
        versions = VERSION_RIB_EXPORTED_STRING_KEY..VERSION_PREFIX_TO_OXNET,
    }]
    async fn get_exported_v6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::session::ExportedSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<String, Vec<v1::rdb::prefix::Prefix>>>,
        HttpError,
    > {
        Ok(Self::get_exported(rqctx, request).await?.map(|m| {
            m.into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        v.into_iter()
                            .map(v1::rdb::prefix::Prefix::from)
                            .collect(),
                    )
                })
                .collect()
        }))
    }

    // Supports IPv4/IPv6, filtering by peer/AFI, and unnumbered peers.
    // NOTE: broken — PeerId enum can't serialize as JSON object key.
    //
    // Required (not provided) because the body needs to query the rdb-backed
    // session table via `Self::Context` to materialize the exported
    // route-set; no purely structural conversion from
    // `latest::ExportedSelector` to the v5 response shape exists.
    #[endpoint {
        method = GET,
        path = "/bgp/status/exported",
        operation_id = "get_exported",
        versions = VERSION_UNNUMBERED..VERSION_RIB_EXPORTED_STRING_KEY,
    }]
    async fn get_exported_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::session::ExportedSelector>,
    ) -> Result<
        HttpResponseOk<
            HashMap<v1::bgp::peer::PeerId, Vec<v1::rdb::prefix::Prefix>>,
        >,
        HttpError,
    >;

    // Old exported endpoint - IPv4 only, no filtering. Required for the
    // same reason as `get_exported_v5`: response data is sourced from the
    // session table at request time and can't be forwarded structurally.
    #[endpoint {
        method = GET,
        path = "/bgp/status/exported",
        operation_id = "get_exported",
        versions = ..VERSION_UNNUMBERED,
    }]
    async fn get_exported_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<IpAddr, Vec<v1::rdb::prefix::Prefix>>>,
        HttpError,
    >;

    // VERSION_UNNUMBERED+: BgpPathProperties.peer is PeerId enum.
    #[endpoint {
        method = GET,
        path = "/rib/status/imported",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn get_rib_imported(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::rib::RibQuery>,
    ) -> Result<HttpResponseOk<latest::rib::Rib>, HttpError>;

    // Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED):
    // BgpPathProperties.peer is IpAddr.
    //
    // The RIB-query family (`get_rib_imported_v2`, `get_imported_v1`,
    // `get_rib_selected_v2`, `get_selected_v1`) is required rather than
    // provided because each version queries a different RIB (imported vs
    // selected) at a different shape, with peer identity changing across
    // versions (IpAddr in v1/v2, PeerId enum in v5+). The conversion
    // cannot be done structurally from the latest response — it has to be
    // produced from the underlying rdb state at the requested version's
    // shape.
    #[endpoint {
        method = GET,
        path = "/rib/status/imported",
        operation_id = "get_rib_imported",
        versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED,
    }]
    async fn get_rib_imported_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // imported moved under /rib/status in VERSION_IPV6_BASIC.
    #[endpoint {
        method = GET,
        path = "/bgp/status/imported",
        operation_id = "get_imported",
        versions = ..VERSION_IPV6_BASIC,
    }]
    async fn get_imported_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // VERSION_UNNUMBERED+: BgpPathProperties.peer is PeerId enum.
    #[endpoint {
        method = GET,
        path = "/rib/status/selected",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn get_rib_selected(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::rib::RibQuery>,
    ) -> Result<HttpResponseOk<latest::rib::Rib>, HttpError>;

    // Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED):
    // BgpPathProperties.peer is IpAddr.
    #[endpoint {
        method = GET,
        path = "/rib/status/selected",
        operation_id = "get_rib_selected",
        versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED,
    }]
    async fn get_rib_selected_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // selected moved under /rib/status in VERSION_IPV6_BASIC.
    #[endpoint {
        method = GET,
        path = "/bgp/status/selected",
        operation_id = "get_selected",
        versions = ..VERSION_IPV6_BASIC,
    }]
    async fn get_selected_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // The `get_neighbors_v{1,2,4}` triple below is required (not provided)
    // because each version returns a per-session shape (`PeerInfo` /
    // `history::PeerInfo` / `config::PeerInfo`) that the server can only
    // populate by walking its live session table via `Self::Context`. The
    // latest response is a `HashMap<String, PeerInfo>` keyed by
    // PeerId-as-string; older versions key by `IpAddr` and carry a
    // strictly-IPv4 numbered peer set, so no purely structural forwarding
    // from the latest exists.
    #[endpoint {
        method = GET,
        path = "/bgp/status/neighbors",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<String, latest::bgp::config::PeerInfo>>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/status/neighbors",
        operation_id = "get_neighbors",
        versions = VERSION_UNNUMBERED..VERSION_PREFIX_TO_OXNET,
    }]
    async fn get_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<String, v4::bgp::config::PeerInfo>>,
        HttpError,
    > {
        Self::get_neighbors(rqctx, request).await.map(|r| {
            r.map(|m| m.into_iter().map(|(k, v)| (k, v.into())).collect())
        })
    }

    #[endpoint {
        method = GET,
        path = "/bgp/status/neighbors",
        operation_id = "get_neighbors",
        versions = VERSION_MP_BGP..VERSION_UNNUMBERED,
    }]
    async fn get_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<IpAddr, v4::bgp::config::PeerInfo>>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/status/neighbors",
        operation_id = "get_neighbors",
        versions = VERSION_IPV6_BASIC..VERSION_MP_BGP,
    }]
    async fn get_neighbors_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<IpAddr, v2::bgp::history::PeerInfo>>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/status/neighbors",
        operation_id = "get_neighbors",
        versions = ..VERSION_IPV6_BASIC,
    }]
    async fn get_neighbors_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::config::AsnSelector>,
    ) -> Result<
        HttpResponseOk<HashMap<IpAddr, v1::bgp::config::PeerInfo>>,
        HttpError,
    >;

    #[endpoint {
        method = POST,
        path = "/bgp/omicron/apply",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn bgp_apply(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V8 API - ApplyRequest with per-AF policies and src_addr/src_port but Prefix4/6 not oxnet.
    #[endpoint {
        method = POST,
        path = "/bgp/omicron/apply",
        operation_id = "bgp_apply",
        versions = VERSION_BGP_SRC_ADDR..VERSION_PREFIX_TO_OXNET,
    }]
    async fn bgp_apply_v8(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::bgp::config::ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::bgp_apply(rqctx, request.map(Into::into)).await
    }

    // V4-V7 API - ApplyRequest with per-AF policies but no src_addr/src_port.
    #[endpoint {
        method = POST,
        path = "/bgp/omicron/apply",
        operation_id = "bgp_apply",
        versions = VERSION_MP_BGP..VERSION_BGP_SRC_ADDR,
    }]
    async fn bgp_apply_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v4::bgp::config::ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::bgp_apply_v8(rqctx, request.map(Into::into)).await
    }

    // V1/V2 API - v1::bgp::config::ApplyRequest with combined import/export policies
    #[endpoint {
        method = POST,
        path = "/bgp/omicron/apply",
        operation_id = "bgp_apply",
        versions = ..VERSION_MP_BGP,
    }]
    async fn bgp_apply_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::bgp_apply_v8(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/history/message",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn message_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::session::MessageHistoryRequest>,
    ) -> Result<
        HttpResponseOk<latest::bgp::session::MessageHistoryResponse>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/history/message",
        operation_id = "message_history",
        versions = VERSION_UNNUMBERED..VERSION_PREFIX_TO_OXNET,
    }]
    async fn message_history_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::session::MessageHistoryRequest>,
    ) -> Result<
        HttpResponseOk<v5::bgp::session::MessageHistoryResponse>,
        HttpError,
    > {
        Ok(Self::message_history(rqctx, request)
            .await?
            .map(v5::bgp::session::MessageHistoryResponse::from))
    }

    // `message_history_v{1,2,4}` and `fsm_history_v2` are required (not
    // provided) because the response is drawn from the in-memory ring
    // buffer on each session via `Self::Context`; the per-version shape
    // requires re-walking the buffer with the right peer-identity
    // representation (IpAddr in v1/v2/v4, PeerId in v5+), not just a
    // structural transform of the latest response.
    #[endpoint {
        method = GET,
        path = "/bgp/history/message",
        operation_id = "message_history",
        versions = VERSION_MP_BGP..VERSION_UNNUMBERED,
    }]
    async fn message_history_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::history::MessageHistoryRequest>,
    ) -> Result<
        HttpResponseOk<v4::bgp::config::MessageHistoryResponse>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/history/message",
        operation_id = "message_history",
        versions = VERSION_IPV6_BASIC..VERSION_MP_BGP,
    }]
    async fn message_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::history::MessageHistoryRequest>,
    ) -> Result<
        HttpResponseOk<v2::bgp::history::MessageHistoryResponse>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/message-history",
        operation_id = "message_history",
        versions = ..VERSION_IPV6_BASIC,
    }]
    async fn message_history_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::config::MessageHistoryRequest>,
    ) -> Result<
        HttpResponseOk<v1::bgp::config::MessageHistoryResponse>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/history/fsm",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn fsm_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::session::FsmHistoryRequest>,
    ) -> Result<
        HttpResponseOk<latest::bgp::session::FsmHistoryResponse>,
        HttpError,
    >;

    #[endpoint {
        method = GET,
        path = "/bgp/history/fsm",
        operation_id = "fsm_history",
        versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED,
    }]
    async fn fsm_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::history::FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<v2::bgp::history::FsmHistoryResponse>, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/checker",
    }]
    async fn create_checker(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/checker",
    }]
    async fn read_checker(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::bgp::config::CheckerSource>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/checker",
    }]
    async fn update_checker(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/checker",
    }]
    async fn delete_checker(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/shaper",
    }]
    async fn create_shaper(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/shaper",
    }]
    async fn read_shaper(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::bgp::config::ShaperSource>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/shaper",
    }]
    async fn update_shaper(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::config::ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/shaper",
    }]
    async fn delete_shaper(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = GET,
        path = "/rib/config/bestpath/fanout",
        versions = VERSION_IPV6_BASIC..,
    }]
    async fn read_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::BestpathFanoutResponse>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/rib/config/bestpath/fanout",
        versions = VERSION_IPV6_BASIC..,
    }]
    async fn update_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::rib::BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bestpath/config/fanout",
        operation_id = "read_bestpath_fanout",
        versions = ..VERSION_IPV6_BASIC,
    }]
    async fn read_bestpath_fanout_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v1::rib::BestpathFanoutResponse>, HttpError>
    {
        Self::read_bestpath_fanout(rqctx).await
    }

    #[endpoint {
        method = POST,
        path = "/bestpath/config/fanout",
        operation_id = "update_bestpath_fanout",
        versions = ..VERSION_IPV6_BASIC,
    }]
    async fn update_bestpath_fanout_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::rib::BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_bestpath_fanout(rqctx, request).await
    }

    #[endpoint {
        method = PUT,
        path = "/static/route4",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn static_add_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/static/route4",
        operation_id = "static_add_v4_route",
        versions = VERSION_V4_OVER_V6_STATIC_ROUTES..VERSION_PREFIX_TO_OXNET,
    }]
    async fn static_add_v4_route_v10(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v10::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::static_add_v4_route(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = PUT,
        path = "/static/route4",
        operation_id = "static_add_v4_route",
        versions = ..VERSION_V4_OVER_V6_STATIC_ROUTES,
    }]
    async fn static_add_v4_route_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::static_add_v4_route_v10(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = DELETE,
        path = "/static/route4",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn static_remove_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/static/route4",
        operation_id = "static_remove_v4_route",
        versions = VERSION_V4_OVER_V6_STATIC_ROUTES..VERSION_PREFIX_TO_OXNET,
    }]
    async fn static_remove_v4_route_v10(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v10::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::static_remove_v4_route(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = DELETE,
        path = "/static/route4",
        operation_id = "static_remove_v4_route",
        versions = ..VERSION_V4_OVER_V6_STATIC_ROUTES,
    }]
    async fn static_remove_v4_route_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::static_remove_v4_route_v10(rqctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/static/route4",
        operation_id = "static_list_v4_routes",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn static_list_v4_routes(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError>;

    // Pre-UNNUMBERED shim: paths use the v1 BgpPathProperties shape
    // (peer is IpAddr rather than PeerId). Operation ID matches the
    // latest endpoint so a single client method covers all versions.
    #[endpoint {
        method = GET,
        path = "/static/route4",
        operation_id = "static_list_v4_routes",
        versions = ..VERSION_UNNUMBERED,
    }]
    async fn static_list_v4_routes_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v1::rib::GetRibResult>, HttpError> {
        let latest = Self::static_list_v4_routes(rqctx).await?.0;
        Ok(HttpResponseOk(v5::rib::get_rib_result_into_v1(latest)))
    }

    // IPv6 static routes introduced in VERSION_IPV6_BASIC
    #[endpoint {
        method = PUT,
        path = "/static/route6",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn static_add_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/static/route6",
        versions = VERSION_PREFIX_TO_OXNET..,
    }]
    async fn static_remove_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/static/route6",
        operation_id = "static_add_v6_route",
        versions = VERSION_IPV6_BASIC..VERSION_PREFIX_TO_OXNET,
    }]
    async fn static_add_v6_route_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::static_routes::AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::static_add_v6_route(ctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = DELETE,
        path = "/static/route6",
        operation_id = "static_remove_v6_route",
        versions = VERSION_IPV6_BASIC..VERSION_PREFIX_TO_OXNET,
    }]
    async fn static_remove_v6_route_v2(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::static_routes::DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::static_remove_v6_route(ctx, request.map(Into::into)).await
    }

    #[endpoint {
        method = GET,
        path = "/static/route6",
        operation_id = "static_list_v6_routes",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn static_list_v6_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError>;

    // Shim for IPV6_BASIC..UNNUMBERED: same v1-shaped Path/BgpPathProperties
    // as the v4 list. Operation-id matches the latest endpoint so the
    // generated client has a single method covering both versions.
    #[endpoint {
        method = GET,
        path = "/static/route6",
        operation_id = "static_list_v6_routes",
        versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED,
    }]
    async fn static_list_v6_routes_v2(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v1::rib::GetRibResult>, HttpError> {
        let latest = Self::static_list_v6_routes(ctx).await?.0;
        Ok(HttpResponseOk(v5::rib::get_rib_result_into_v1(latest)))
    }

    #[endpoint {
        method = GET,
        path = "/switch/identifiers",
        versions = VERSION_SWITCH_IDENTIFIERS..,
    }]
    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::switch::SwitchIdentifiers>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/ndp/manager",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn get_ndp_manager_state(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::ndp::NdpManagerState>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/ndp/interfaces",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn get_ndp_interfaces(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::config::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<latest::ndp::NdpInterface>>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/ndp/interface",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn get_ndp_interface_detail(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::ndp::NdpInterfaceSelector>,
    ) -> Result<HttpResponseOk<latest::ndp::NdpInterface>, HttpError>;

    // MRIB: Multicast ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// Get imported multicast routes from `mrib_in`.
    #[endpoint { method = GET, path = "/mrib/status/imported", versions = VERSION_MULTICAST_SUPPORT.. }]
    async fn get_mrib_imported(
        rqctx: RequestContext<Self::Context>,
        query: Query<latest::mrib::MribQuery>,
    ) -> Result<HttpResponseOk<Vec<latest::mrib::MulticastRoute>>, HttpError>;

    /// Get selected multicast routes from `mrib_loc` (RPF-validated).
    #[endpoint { method = GET, path = "/mrib/status/selected", versions = VERSION_MULTICAST_SUPPORT.. }]
    async fn get_mrib_selected(
        rqctx: RequestContext<Self::Context>,
        query: Query<latest::mrib::MribQuery>,
    ) -> Result<HttpResponseOk<Vec<latest::mrib::MulticastRoute>>, HttpError>;

    /// Add static multicast routes.
    #[endpoint { method = PUT, path = "/static/mroute", versions = VERSION_MULTICAST_SUPPORT.. }]
    async fn static_add_mcast_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::mrib::MribAddStaticRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove static multicast routes.
    #[endpoint { method = DELETE, path = "/static/mroute", versions = VERSION_MULTICAST_SUPPORT.. }]
    async fn static_remove_mcast_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::mrib::MribDeleteStaticRequest>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// List all static multicast routes from persistence.
    #[endpoint { method = GET, path = "/static/mroute", versions = VERSION_MULTICAST_SUPPORT.. }]
    async fn static_list_mcast_routes(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::mrib::MulticastRoute>>, HttpError>;
}
