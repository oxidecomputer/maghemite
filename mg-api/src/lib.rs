// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;

use bgp::params::{
    ApplyRequest, ApplyRequestV1, ApplyRequestV2, CheckerSource, Neighbor,
    NeighborV1, NeighborV2, Origin4, Origin6, PeerInfo, PeerInfoV1, PeerInfoV2,
    PeerInfoV3, Router, ShaperSource, UnnumberedNeighbor, UnnumberedNeighborV1,
};
use bgp::session::PeerId;
use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use mg_types_versions::{latest, v1, v2, v5, v8};
use rdb::{BfdPeerConfig, Prefix};

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
    (8, SPRING_CLEANING),
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

    // BFD ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = GET, path = "/bfd/peers" }]
    async fn get_bfd_peers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::bfd::BfdPeerInfo>>, HttpError>;

    #[endpoint { method = PUT, path = "/bfd/peers" }]
    async fn add_bfd_peer(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<BfdPeerConfig>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bfd/peers/{addr}" }]
    async fn remove_bfd_peer(
        rqctx: RequestContext<Self::Context>,
        params: Path<latest::bfd::DeleteBfdPeerPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // Router config ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = GET, path = "/bgp/config/routers" }]
    async fn read_routers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<Router>>, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/router" }]
    async fn create_router(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/router" }]
    async fn read_router(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Router>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/router" }]
    async fn update_router(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/router" }]
    async fn delete_router(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // Neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - Neighbor with DSCP support
    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_SPRING_CLEANING.. }]
    async fn create_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_SPRING_CLEANING.. }]
    async fn read_neighbor(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors/{asn}", versions = VERSION_SPRING_CLEANING.. }]
    async fn read_neighbors(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_SPRING_CLEANING.. }]
    async fn update_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_SPRING_CLEANING.. }]
    async fn delete_neighbor(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - NeighborV2 (no DSCP)
    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn create_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV2>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_neighbor(rqctx, request.map(Neighbor::from)).await
    }

    #[endpoint { method = GET, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn read_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV2>, HttpError> {
        Self::read_neighbor(rqctx, path)
            .await
            .map(|r| r.map(NeighborV2::from))
    }

    #[endpoint { method = GET, path = "/bgp/config/neighbors/{asn}", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn read_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV2>>, HttpError> {
        Self::read_neighbors(rqctx, path)
            .await
            .map(|r| r.map(|v| v.into_iter().map(NeighborV2::from).collect()))
    }

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn update_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV2>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_neighbor(rqctx, request.map(Neighbor::from)).await
    }

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn delete_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::delete_neighbor(rqctx, path).await
    }

    // V4 (VERSION_MP_BGP..VERSION_UNNUMBERED) - NeighborV2 with query params
    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn create_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV2>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_neighbor(rqctx, request.map(Neighbor::from)).await
    }

    #[endpoint { method = GET, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn read_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV2>, HttpError> {
        let rq = request.into_inner();
        Self::read_neighbor(
            rqctx,
            latest::bgp::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
        .map(|r| r.map(NeighborV2::from))
    }

    #[endpoint { method = GET, path = "/bgp/config/neighbors", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn read_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV2>>, HttpError> {
        Self::read_neighbors(rqctx, request.into_inner().into())
            .await
            .map(|r| r.map(|v| v.into_iter().map(NeighborV2::from).collect()))
    }

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn update_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV2>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_neighbor(rqctx, request.map(Neighbor::from)).await
    }

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn delete_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let rq = request.into_inner();
        Self::delete_neighbor(
            rqctx,
            latest::bgp::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    // V1/V2 (..VERSION_MP_BGP) - legacy NeighborV1
    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn create_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn read_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV1>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors", versions = ..VERSION_MP_BGP }]
    async fn read_neighbors_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV1>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn update_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn delete_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let rq = request.into_inner();
        Self::delete_neighbor(
            rqctx,
            latest::bgp::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    // Clear neighbor ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = POST, path = "/bgp/clear/neighbor", versions = VERSION_MP_BGP.. }]
    async fn clear_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = POST, path = "/bgp/clear/neighbor", versions = ..VERSION_MP_BGP }]
    async fn clear_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::clear_neighbor(rqctx, request.map(Into::into)).await
    }

    // Unnumbered neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - UnnumberedNeighbor with DSCP
    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbors",
        versions = VERSION_SPRING_CLEANING..,
    }]
    async fn read_unnumbered_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<UnnumberedNeighbor>>, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_SPRING_CLEANING..,
    }]
    async fn create_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_SPRING_CLEANING..,
    }]
    async fn read_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<UnnumberedNeighbor>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_SPRING_CLEANING..,
    }]
    async fn update_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_SPRING_CLEANING..,
    }]
    async fn delete_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - no DSCP
    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbors",
        versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING,
    }]
    async fn read_unnumbered_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<UnnumberedNeighborV1>>, HttpError> {
        Self::read_unnumbered_neighbors(rqctx, request)
            .await
            .map(|r| {
                r.map(|v| {
                    v.into_iter().map(UnnumberedNeighborV1::from).collect()
                })
            })
    }

    #[endpoint {
        method = PUT,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING,
    }]
    async fn create_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_unnumbered_neighbor(
            rqctx,
            request.map(UnnumberedNeighbor::from),
        )
        .await
    }

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING,
    }]
    async fn read_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<UnnumberedNeighborV1>, HttpError> {
        Self::read_unnumbered_neighbor(rqctx, request)
            .await
            .map(|r| r.map(UnnumberedNeighborV1::from))
    }

    #[endpoint {
        method = POST,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING,
    }]
    async fn update_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_unnumbered_neighbor(
            rqctx,
            request.map(UnnumberedNeighbor::from),
        )
        .await
    }

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING,
    }]
    async fn delete_unnumbered_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::delete_unnumbered_neighbor(rqctx, request).await
    }

    // Clear unnumbered neighbor
    #[endpoint { method = POST, path = "/bgp/clear/unnumbered-neighbor", versions = VERSION_UNNUMBERED.. }]
    async fn clear_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::UnnumberedNeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // IPv4 origin ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = PUT, path = "/bgp/config/origin4" }]
    async fn create_origin4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/origin4" }]
    async fn read_origin4(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Origin4>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/origin4" }]
    async fn update_origin4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/origin4" }]
    async fn delete_origin4(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn create_origin6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn read_origin6(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Origin6>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn update_origin6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn delete_origin6(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // Exported ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = GET, path = "/bgp/status/exported", versions = VERSION_RIB_EXPORTED_STRING_KEY.. }]
    async fn get_exported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, Vec<Prefix>>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/exported", versions = VERSION_UNNUMBERED..VERSION_RIB_EXPORTED_STRING_KEY }]
    async fn get_exported_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<PeerId, Vec<Prefix>>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/exported", versions = ..VERSION_UNNUMBERED }]
    async fn get_exported_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError>;

    // RIB imported/selected ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - RibQuery with prefix filter
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_SPRING_CLEANING.. }]
    async fn get_rib_imported(
        rqctx: RequestContext<Self::Context>,
        request: Query<v8::rib::RibQuery>,
    ) -> Result<HttpResponseOk<latest::rib::Rib>, HttpError>;

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - no prefix filter,
    // PathV2 (without origin/internal/peer_ip).
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn get_rib_imported_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v5::rib::Rib>, HttpError>;

    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn get_rib_imported_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/imported", versions = ..VERSION_IPV6_BASIC }]
    async fn get_imported_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // Latest (VERSION_SPRING_CLEANING..) - RibQuery with prefix filter
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_SPRING_CLEANING.. }]
    async fn get_rib_selected(
        rqctx: RequestContext<Self::Context>,
        request: Query<v8::rib::RibQuery>,
    ) -> Result<HttpResponseOk<latest::rib::Rib>, HttpError>;

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - no prefix filter,
    // PathV2 (without origin/internal/peer_ip).
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn get_rib_selected_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v5::rib::Rib>, HttpError>;

    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn get_rib_selected_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/selected", versions = ..VERSION_IPV6_BASIC }]
    async fn get_selected_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // Neighbors status ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - PeerInfo with per-AFI counters
    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_SPRING_CLEANING.. }]
    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError>;

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - PeerInfoV3
    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn get_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, PeerInfoV3>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn get_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV3>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_IPV6_BASIC..VERSION_MP_BGP }]
    async fn get_neighbors_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = ..VERSION_IPV6_BASIC }]
    async fn get_neighbors_v1(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError>;

    // Apply ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - ApplyRequest with DSCP
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = VERSION_SPRING_CLEANING.. }]
    async fn bgp_apply(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V4 (VERSION_MP_BGP..VERSION_SPRING_CLEANING) - ApplyRequestV2 (no DSCP)
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = VERSION_MP_BGP..VERSION_SPRING_CLEANING }]
    async fn bgp_apply_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequestV2>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::bgp_apply(rqctx, request.map(ApplyRequest::from)).await
    }

    // V1 (..VERSION_MP_BGP) - ApplyRequestV1
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = ..VERSION_MP_BGP }]
    async fn bgp_apply_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequestV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::bgp_apply(rqctx, request.map(Into::into)).await
    }

    // Message history ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - buffer selection, flat entries
    #[endpoint { method = GET, path = "/bgp/history/message", versions = VERSION_SPRING_CLEANING.. }]
    async fn message_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v8::bgp::MessageHistoryResponse>, HttpError>;

    // V5 (VERSION_UNNUMBERED..VERSION_SPRING_CLEANING) - PeerId support
    #[endpoint { method = GET, path = "/bgp/history/message", versions = VERSION_UNNUMBERED..VERSION_SPRING_CLEANING }]
    async fn message_history_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v5::bgp::MessageHistoryResponse>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/history/message", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn message_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v2::bgp::MessageHistoryResponse>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/message-history", versions = ..VERSION_IPV6_BASIC }]
    async fn message_history_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<v1::bgp::MessageHistoryResponse>, HttpError>;

    // FSM history ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = GET, path = "/bgp/history/fsm", versions = VERSION_UNNUMBERED.. }]
    async fn fsm_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<latest::bgp::FsmHistoryResponse>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/history/fsm", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn fsm_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v2::bgp::FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<v2::bgp::FsmHistoryResponse>, HttpError>;

    // Checker/Shaper ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = PUT, path = "/bgp/config/checker" }]
    async fn create_checker(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/checker" }]
    async fn read_checker(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<CheckerSource>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/checker" }]
    async fn update_checker(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/checker" }]
    async fn delete_checker(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/shaper" }]
    async fn create_shaper(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/shaper" }]
    async fn read_shaper(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<ShaperSource>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/shaper" }]
    async fn update_shaper(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/shaper" }]
    async fn delete_shaper(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // Bestpath fanout ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = GET, path = "/rib/config/bestpath/fanout", versions = VERSION_IPV6_BASIC.. }]
    async fn read_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::BestpathFanoutResponse>, HttpError>;

    #[endpoint { method = POST, path = "/rib/config/bestpath/fanout", versions = VERSION_IPV6_BASIC.. }]
    async fn update_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::rib::BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bestpath/config/fanout", versions = ..VERSION_IPV6_BASIC }]
    async fn read_bestpath_fanout_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v1::rib::BestpathFanoutResponse>, HttpError>
    {
        Self::read_bestpath_fanout(rqctx).await
    }

    #[endpoint { method = POST, path = "/bestpath/config/fanout", versions = ..VERSION_IPV6_BASIC }]
    async fn update_bestpath_fanout_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::rib::BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_bestpath_fanout(rqctx, request).await
    }

    // Static routes ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest (VERSION_SPRING_CLEANING..) - IpAddr nexthop + interface
    #[endpoint { method = PUT, path = "/static/route4", versions = VERSION_SPRING_CLEANING.. }]
    async fn static_add_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route4", versions = VERSION_SPRING_CLEANING.. }]
    async fn static_remove_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v8::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route4", versions = VERSION_SPRING_CLEANING.. }]
    async fn static_list_v4_routes(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError>;

    #[endpoint { method = PUT, path = "/static/route6", versions = VERSION_SPRING_CLEANING.. }]
    async fn static_add_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v8::static_routes::AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route6", versions = VERSION_SPRING_CLEANING.. }]
    async fn static_remove_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v8::static_routes::DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route6", versions = VERSION_SPRING_CLEANING.. }]
    async fn static_list_v6_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError>;

    // V1 static routes (..VERSION_SPRING_CLEANING) - typed nexthop
    #[endpoint { method = PUT, path = "/static/route4", versions = ..VERSION_SPRING_CLEANING }]
    async fn static_add_v4_route_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route4", versions = ..VERSION_SPRING_CLEANING }]
    async fn static_remove_v4_route_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route4", versions = ..VERSION_SPRING_CLEANING }]
    async fn static_list_v4_routes_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError> {
        Self::static_list_v4_routes(rqctx).await
    }

    #[endpoint { method = PUT, path = "/static/route6", versions = VERSION_IPV6_BASIC..VERSION_SPRING_CLEANING }]
    async fn static_add_v6_route_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::static_routes::AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route6", versions = VERSION_IPV6_BASIC..VERSION_SPRING_CLEANING }]
    async fn static_remove_v6_route_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v2::static_routes::DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route6", versions = VERSION_IPV6_BASIC..VERSION_SPRING_CLEANING }]
    async fn static_list_v6_routes_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError> {
        Self::static_list_v6_routes(ctx).await
    }

    // Switch identifiers ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint {method = GET, path = "/switch/identifiers", versions = VERSION_SWITCH_IDENTIFIERS.. }]
    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::switch::SwitchIdentifiers>, HttpError>;

    // NDP ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = GET, path = "/ndp/manager", versions = VERSION_UNNUMBERED.. }]
    async fn get_ndp_manager_state(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<latest::ndp::NdpManagerState>, HttpError>;

    #[endpoint { method = GET, path = "/ndp/interfaces", versions = VERSION_UNNUMBERED.. }]
    async fn get_ndp_interfaces(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<latest::ndp::NdpInterface>>, HttpError>;

    #[endpoint { method = GET, path = "/ndp/interface", versions = VERSION_UNNUMBERED.. }]
    async fn get_ndp_interface_detail(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::ndp::NdpInterfaceSelector>,
    ) -> Result<HttpResponseOk<latest::ndp::NdpInterface>, HttpError>;
}
