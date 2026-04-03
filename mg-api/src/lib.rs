// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::net::IpAddr;

use bgp::params::{
    ApplyRequest, ApplyRequestV1, ApplyRequestV6, CheckerSource, Neighbor,
    NeighborV1, NeighborV6, Origin4, Origin6, PeerInfo, PeerInfoV1, PeerInfoV2,
    Router, ShaperSource, UnnumberedNeighbor, UnnumberedNeighborV6,
};
use bgp::session::PeerId;
use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use mg_types_versions::{latest, v1, v2, v5};
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
    #[endpoint { method = GET, path = "/bfd/peers" }]
    async fn get_bfd_peers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::bfd::BfdPeerInfo>>, HttpError>;

    /// Add a new peer to the daemon. A session for the specified peer will start
    /// immediately.
    #[endpoint { method = PUT, path = "/bfd/peers" }]
    async fn add_bfd_peer(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<BfdPeerConfig>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove the specified peer from the daemon. The associated peer session will
    /// be stopped immediately.
    #[endpoint { method = DELETE, path = "/bfd/peers/{addr}" }]
    async fn remove_bfd_peer(
        rqctx: RequestContext<Self::Context>,
        params: Path<latest::bfd::DeleteBfdPeerPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

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

    // Latest API (VERSION_BGP_SRC_ADDR..) - supports src_addr/src_port for
    // per-neighbor source address binding.

    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn create_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn read_neighbor(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors/{asn}", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn read_neighbors(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn update_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn delete_neighbor(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V5 API (VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR) - supports both
    // numbered and unnumbered neighbors but lacks src_addr/src_port.

    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn create_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn read_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV6>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors/{asn}", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn read_neighbors_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV6>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn update_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn delete_neighbor_v5(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V4 API - new Neighbor type with explicit per-AF configuration (numbered
    // peers only). create and update take NeighborV6 (same schema as V5);
    // read and delete use a different selector type.

    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn create_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::create_neighbor_v5(rqctx, request).await
    }

    #[endpoint { method = GET, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn read_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseOk<NeighborV6>, HttpError> {
        let rq = request.into_inner();
        Self::read_neighbor_v5(
            rqctx,
            latest::bgp::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    #[endpoint { method = GET, path = "/bgp/config/neighbors", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn read_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV6>>, HttpError> {
        Self::read_neighbors_v5(rqctx, request.into_inner().into()).await
    }

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn update_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::update_neighbor_v5(rqctx, request).await
    }

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn delete_neighbor_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let rq = request.into_inner();
        Self::delete_neighbor_v5(
            rqctx,
            latest::bgp::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    // V1/V2 API - legacy Neighbor type with combined import/export policies

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
        Self::delete_neighbor_v5(
            rqctx,
            latest::bgp::NeighborSelector {
                asn: rq.asn,
                peer: rq.addr.to_string(),
            }
            .into(),
        )
        .await
    }

    // V4+ API clear neighbor with per-AF support
    #[endpoint { method = POST, path = "/bgp/clear/neighbor", versions = VERSION_MP_BGP.. }]
    async fn clear_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V1/V2 API clear neighbor (backwards compatibility w/ IPv4 only support)
    #[endpoint { method = POST, path = "/bgp/clear/neighbor", versions = ..VERSION_MP_BGP }]
    async fn clear_neighbor_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::clear_neighbor(rqctx, request.map(Into::into)).await
    }

    // Unnumbered neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    // Latest API (VERSION_BGP_SRC_ADDR..) - supports src_addr/src_port.

    #[endpoint { method = GET, path = "/bgp/config/unnumbered-neighbors", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn read_unnumbered_neighbors_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<UnnumberedNeighbor>>, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn create_unnumbered_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn read_unnumbered_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<UnnumberedNeighbor>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn update_unnumbered_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn delete_unnumbered_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V5 API (VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR) - unnumbered neighbors
    // without src_addr/src_port.

    #[endpoint { method = GET, path = "/bgp/config/unnumbered-neighbors", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn read_unnumbered_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<UnnumberedNeighborV6>>, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn create_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighborV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn read_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<UnnumberedNeighborV6>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn update_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighborV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/unnumbered-neighbor", versions = VERSION_UNNUMBERED..VERSION_BGP_SRC_ADDR }]
    async fn delete_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

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

    // Fixed: uses String keys from PeerId Display (e.g. "192.0.2.1" or
    // "tfportqsfp0_0").
    #[endpoint { method = GET, path = "/bgp/status/exported", versions = VERSION_RIB_EXPORTED_STRING_KEY.. }]
    async fn get_exported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, Vec<Prefix>>>, HttpError>;

    // Supports IPv4/IPv6, filtering by peer/AFI, and unnumbered peers.
    // NOTE: broken — PeerId enum can't serialize as JSON object key.
    #[endpoint { method = GET, path = "/bgp/status/exported", versions = VERSION_UNNUMBERED..VERSION_RIB_EXPORTED_STRING_KEY }]
    async fn get_exported_v5(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v5::bgp::ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<PeerId, Vec<Prefix>>>, HttpError>;

    // Old exported endpoint - IPv4 only, no filtering.
    #[endpoint { method = GET, path = "/bgp/status/exported", versions = ..VERSION_UNNUMBERED }]
    async fn get_exported_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError>;

    // VERSION_UNNUMBERED+: BgpPathProperties.peer is PeerId enum.
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_UNNUMBERED.. }]
    async fn get_rib_imported(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::rib::RibQuery>,
    ) -> Result<HttpResponseOk<latest::rib::Rib>, HttpError>;

    // Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED):
    // BgpPathProperties.peer is IpAddr.
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn get_rib_imported_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // imported moved under /rib/status in VERSION_IPV6_BASIC.
    #[endpoint { method = GET, path = "/bgp/status/imported", versions = ..VERSION_IPV6_BASIC }]
    async fn get_imported_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // VERSION_UNNUMBERED+: BgpPathProperties.peer is PeerId enum.
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_UNNUMBERED.. }]
    async fn get_rib_selected(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::rib::RibQuery>,
    ) -> Result<HttpResponseOk<latest::rib::Rib>, HttpError>;

    // Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED):
    // BgpPathProperties.peer is IpAddr.
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn get_rib_selected_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<v2::rib::RibQuery>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    // selected moved under /rib/status in VERSION_IPV6_BASIC.
    #[endpoint { method = GET, path = "/bgp/status/selected", versions = ..VERSION_IPV6_BASIC }]
    async fn get_selected_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_UNNUMBERED.. }]
    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<latest::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn get_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<v1::bgp::AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfo>>, HttpError>;

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

    // Latest API - ApplyRequest with per-AF policies and src_addr/src_port
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = VERSION_BGP_SRC_ADDR.. }]
    async fn bgp_apply_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V4-V7 API - ApplyRequestV6 with per-AF policies but no src_addr/src_port
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = VERSION_MP_BGP..VERSION_BGP_SRC_ADDR }]
    async fn bgp_apply(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequestV6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V1/V2 API - ApplyRequestV1 with combined import/export policies
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = ..VERSION_MP_BGP }]
    async fn bgp_apply_v1(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequestV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::bgp_apply_v2(rqctx, request.map(Into::into)).await
    }

    #[endpoint { method = GET, path = "/bgp/history/message", versions = VERSION_UNNUMBERED.. }]
    async fn message_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::bgp::MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<latest::bgp::MessageHistoryResponse>, HttpError>;

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

    #[endpoint { method = PUT, path = "/static/route4" }]
    async fn static_add_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route4" }]
    async fn static_remove_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route4" }]
    async fn static_list_v4_routes(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError>;

    // IPv6 static routes introduced in VERSION_IPV6_BASIC
    #[endpoint { method = PUT, path = "/static/route6", versions = VERSION_IPV6_BASIC.. }]
    async fn static_add_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route6", versions = VERSION_IPV6_BASIC.. }]
    async fn static_remove_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::static_routes::DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route6", versions = VERSION_IPV6_BASIC.. }]
    async fn static_list_v6_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::rib::GetRibResult>, HttpError>;

    #[endpoint { method = GET, path = "/switch/identifiers", versions = VERSION_SWITCH_IDENTIFIERS.. }]
    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::switch::SwitchIdentifiers>, HttpError>;

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
