// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU8,
};

use bfd::BfdPeerState;
use bgp::{
    messages::Afi,
    params::{
        ApplyRequest, ApplyRequestV1, CheckerSource, Neighbor, NeighborResetOp,
        NeighborResetOpV1, NeighborV1, Origin4, Origin6, PeerInfo, PeerInfoV1,
        PeerInfoV2, Router, ShaperSource, UnnumberedNeighbor,
    },
    session::{FsmEventRecord, MessageHistory, MessageHistoryV1, PeerId},
};
use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use rdb::{
    BfdPeerConfig, Path as RdbPath, PathV1, Prefix, Prefix4, Prefix6,
    StaticRouteKey,
    types::{AddressFamily, ProtocolFilter},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    (6, EXPORTED_FIX),
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
    ) -> Result<HttpResponseOk<Vec<BfdPeerInfo>>, HttpError>;

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
        params: Path<DeleteBfdPeerPathParams>,
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
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Router>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/router" }]
    async fn update_router(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Router>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/router" }]
    async fn delete_router(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V1/V2 API - legacy Neighbor type with combined import/export policies

    // Neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn create_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn read_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<NeighborSelectorV1>,
    ) -> Result<HttpResponseOk<NeighborV1>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors", versions = ..VERSION_MP_BGP }]
    async fn read_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NeighborV1>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn update_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor", versions = ..VERSION_MP_BGP }]
    async fn delete_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<NeighborSelectorV1>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V3 API - new Neighbor type with explicit per-AF configuration (numbered peers only)
    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn create_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn read_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<NeighborSelectorV1>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn read_neighbors_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn update_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn delete_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<NeighborSelectorV1>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // Unified API (VERSION_UNNUMBERED..) - supports both numbered and unnumbered neighbors
    // Uses PeerId in path parameters with FromStr for type-safe parsing
    #[endpoint { method = PUT, path = "/bgp/config/neighbor", versions = VERSION_UNNUMBERED.. }]
    async fn create_neighbor_v3(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_UNNUMBERED.. }]
    async fn read_neighbor_v3(
        rqctx: RequestContext<Self::Context>,
        path: Path<NeighborSelector>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbors/{asn}", versions = VERSION_UNNUMBERED.. }]
    async fn read_neighbors_v3(
        rqctx: RequestContext<Self::Context>,
        path: Path<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor", versions = VERSION_UNNUMBERED.. }]
    async fn update_neighbor_v3(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor/{asn}/{peer}", versions = VERSION_UNNUMBERED.. }]
    async fn delete_neighbor_v3(
        rqctx: RequestContext<Self::Context>,
        path: Path<NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // V1/V2 API clear neighbor (backwards compatibility w/ IPv4 only support)
    #[endpoint { method = POST, path = "/bgp/clear/neighbor", versions = ..VERSION_MP_BGP }]
    async fn clear_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborResetRequestV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V3 API clear neighbor with per-AF support
    #[endpoint { method = POST, path = "/bgp/clear/neighbor", versions = VERSION_MP_BGP.. }]
    async fn clear_neighbor_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // Unnumbered neighbors ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbors",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn read_unnumbered_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<UnnumberedNeighbor>>, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn create_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn read_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseOk<UnnumberedNeighbor>, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn update_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/bgp/config/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn delete_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<UnnumberedNeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint {
        method = POST,
        path = "/bgp/clear/unnumbered-neighbor",
        versions = VERSION_UNNUMBERED..,
    }]
    async fn clear_unnumbered_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<UnnumberedNeighborResetRequest>,
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
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Origin4>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/origin4" }]
    async fn update_origin4(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin4>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/origin4" }]
    async fn delete_origin4(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn create_origin6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn read_origin6(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Origin6>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn update_origin6(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Origin6>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/origin6", versions = VERSION_IPV6_BASIC.. }]
    async fn delete_origin6(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    // Old exported endpoint - IPv4 only, no filtering
    #[endpoint { method = GET, path = "/bgp/status/exported", versions = ..VERSION_UNNUMBERED }]
    async fn get_exported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError>;

    // Supports IPv4/IPv6, filtering by peer/AFI, and unnumbered peers
    // NOTE: broken — PeerId enum can't serialize as JSON object key
    #[endpoint { method = GET, path = "/bgp/status/exported", versions = VERSION_UNNUMBERED..VERSION_EXPORTED_FIX }]
    async fn get_exported_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<PeerId, Vec<Prefix>>>, HttpError>;

    // Fixed: uses String keys from PeerId Display (e.g. "192.0.2.1" or "tfportqsfp0_0")
    #[endpoint { method = GET, path = "/bgp/status/exported", versions = VERSION_EXPORTED_FIX.. }]
    async fn get_exported_v3(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ExportedSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, Vec<Prefix>>>, HttpError>;

    // imported moved under /rib/status in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/bgp/status/imported", versions = ..VERSION_IPV6_BASIC }]
    async fn get_imported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<RibV1>, HttpError>;

    // exported moved under /rib/status in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/bgp/status/selected", versions = ..VERSION_IPV6_BASIC }]
    async fn get_selected(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<RibV1>, HttpError>;

    // Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED): BgpPathProperties.peer is IpAddr
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn get_rib_imported(
        rqctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<RibV1>, HttpError>;

    // Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED): BgpPathProperties.peer is IpAddr
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn get_rib_selected(
        rqctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<RibV1>, HttpError>;

    // VERSION_UNNUMBERED+: BgpPathProperties.peer is PeerId enum
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_UNNUMBERED.. }]
    async fn get_rib_imported_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError>;

    // VERSION_UNNUMBERED+: BgpPathProperties.peer is PeerId enum
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_UNNUMBERED.. }]
    async fn get_rib_selected_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = ..VERSION_IPV6_BASIC }]
    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_IPV6_BASIC..VERSION_MP_BGP }]
    async fn get_neighbors_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_MP_BGP..VERSION_UNNUMBERED }]
    async fn get_neighbors_v3(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfo>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_UNNUMBERED.. }]
    async fn get_neighbors_v4(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<String, PeerInfo>>, HttpError>;

    // V1/V2 API - ApplyRequestV1 with combined import/export policies
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = ..VERSION_MP_BGP }]
    async fn bgp_apply(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequestV1>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // V3 API - ApplyRequest with per-AF policies
    #[endpoint { method = POST, path = "/bgp/omicron/apply", versions = VERSION_MP_BGP.. }]
    async fn bgp_apply_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/message-history", versions = ..VERSION_IPV6_BASIC }]
    async fn message_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequestV1>,
    ) -> Result<HttpResponseOk<MessageHistoryResponseV1>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/history/message", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn message_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequestV4>,
    ) -> Result<HttpResponseOk<MessageHistoryResponseV4>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/history/message", versions = VERSION_UNNUMBERED.. }]
    async fn message_history_v3(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/history/fsm", versions = VERSION_IPV6_BASIC..VERSION_UNNUMBERED }]
    async fn fsm_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<FsmHistoryRequestV4>,
    ) -> Result<HttpResponseOk<FsmHistoryResponseV4>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/history/fsm", versions = VERSION_UNNUMBERED.. }]
    async fn fsm_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<FsmHistoryRequest>,
    ) -> Result<HttpResponseOk<FsmHistoryResponse>, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/checker" }]
    async fn create_checker(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/checker" }]
    async fn read_checker(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<CheckerSource>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/checker" }]
    async fn update_checker(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<CheckerSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/checker" }]
    async fn delete_checker(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/shaper" }]
    async fn create_shaper(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/shaper" }]
    async fn read_shaper(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<ShaperSource>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/shaper" }]
    async fn update_shaper(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ShaperSource>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/shaper" }]
    async fn delete_shaper(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/bestpath/config/fanout", versions = ..VERSION_IPV6_BASIC }]
    async fn read_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError>;

    #[endpoint { method = POST, path = "/bestpath/config/fanout", versions = ..VERSION_IPV6_BASIC }]
    async fn update_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // bestpath fanout moved under /rib/config/bestpath in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/rib/config/bestpath/fanout", versions = VERSION_IPV6_BASIC.. }]
    async fn read_rib_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError>;

    #[endpoint { method = POST, path = "/rib/config/bestpath/fanout", versions = VERSION_IPV6_BASIC.. }]
    async fn update_rib_bestpath_fanout(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<BestpathFanoutRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = PUT, path = "/static/route4" }]
    async fn static_add_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AddStaticRoute4Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route4" }]
    async fn static_remove_v4_route(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<DeleteStaticRoute4Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route4" }]
    async fn static_list_v4_routes(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<GetRibResult>, HttpError>;

    // IPv6 static routes introduced in VERSION_IPV6_BASIC
    #[endpoint { method = PUT, path = "/static/route6", versions = VERSION_IPV6_BASIC.. }]
    async fn static_add_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<AddStaticRoute6Request>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/static/route6", versions = VERSION_IPV6_BASIC.. }]
    async fn static_remove_v6_route(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<DeleteStaticRoute6Request>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = GET, path = "/static/route6", versions = VERSION_IPV6_BASIC.. }]
    async fn static_list_v6_routes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<GetRibResult>, HttpError>;

    #[endpoint {method = GET, path = "/switch/identifiers", versions = VERSION_SWITCH_IDENTIFIERS.. }]
    async fn switch_identifiers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError>;

    #[endpoint { method = GET, path = "/ndp/manager", versions = VERSION_UNNUMBERED.. }]
    async fn get_ndp_manager_state(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<NdpManagerState>, HttpError>;

    #[endpoint { method = GET, path = "/ndp/interfaces", versions = VERSION_UNNUMBERED.. }]
    async fn get_ndp_interfaces(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<NdpInterface>>, HttpError>;

    #[endpoint { method = GET, path = "/ndp/interface", versions = VERSION_UNNUMBERED.. }]
    async fn get_ndp_interface_detail(
        rqctx: RequestContext<Self::Context>,
        request: Query<NdpInterfaceSelector>,
    ) -> Result<HttpResponseOk<NdpInterface>, HttpError>;
}

/// Identifiers for a switch.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct SwitchIdentifiers {
    /// The slot number of the switch being managed.
    ///
    /// MGS uses u16 for this internally.
    pub slot: Option<u16>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BfdPeerInfo {
    pub config: BfdPeerConfig,
    pub state: BfdPeerState,
}

/// Request to remove a peer from the daemon.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DeleteBfdPeerPathParams {
    /// Address of the peer to remove.
    pub addr: IpAddr,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AsnSelector {
    /// ASN of the router to get imported prefixes from.
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExportedSelector {
    /// ASN of the router to get exported prefixes from.
    pub asn: u32,
    /// Optional peer filter using PeerId enum
    pub peer: Option<PeerId>,
    /// Optional address family filter (None = all negotiated families)
    pub afi: Option<Afi>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteRouterRequest {
    /// Autonomous system number for the router to remove
    pub asn: u32,
}

// ============================================================================
// Archived API Types (Pre-VERSION_UNNUMBERED)
// ============================================================================

/// V1 API NeighborSelector (numbered peers only)
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "NeighborSelector")]
pub struct NeighborSelectorV1 {
    pub asn: u32,
    pub addr: IpAddr,
}

// ============================================================================
// Current API Types (VERSION_UNNUMBERED and later)
// ============================================================================

/// V1 Rib with PathV1
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "Rib")]
pub struct RibV1(BTreeMap<String, BTreeSet<PathV1>>);

impl From<rdb::db::Rib> for RibV1 {
    fn from(value: rdb::db::Rib) -> Self {
        RibV1(
            value
                .into_iter()
                .map(|(k, v)| {
                    let paths_v1: BTreeSet<PathV1> =
                        v.into_iter().map(PathV1::from).collect();
                    (k.to_string(), paths_v1)
                })
                .collect(),
        )
    }
}

/// Unified neighbor selector supporting both numbered and unnumbered peers
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborSelector {
    pub asn: u32,
    /// Peer identifier as a string.
    ///
    /// - For numbered peers: IP address (e.g., "192.0.2.1" or "2001:db8::1")
    /// - For unnumbered peers: Interface name (e.g., "eth0" or "cxgbe0")
    ///
    /// Server parses as IP address first; if parsing fails, treats as interface name.
    /// Uses PeerId::from_str() for type-safe conversion.
    pub peer: String,
}

impl NeighborSelector {
    /// Convert peer string to PeerId using FromStr implementation.
    /// Tries to parse as IP first, otherwise treats as interface name.
    pub fn to_peer_id(&self) -> bgp::session::PeerId {
        self.peer.parse().expect("PeerId::from_str never fails")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[schemars(rename = "NeighborResetRequest")]
pub struct NeighborResetRequestV1 {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOpV1,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedNeighborSelector {
    pub asn: u32,
    pub interface: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOp,
}

impl std::fmt::Display for NeighborResetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "neighbor {} asn {} op {:?}",
            self.addr, self.asn, self.op
        )
    }
}

impl From<NeighborResetRequestV1> for NeighborResetRequest {
    fn from(req: NeighborResetRequestV1) -> Self {
        Self {
            asn: req.asn,
            addr: req.addr,
            op: req.op.into(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct UnnumberedNeighborResetRequest {
    pub asn: u32,
    pub interface: String,
    pub op: NeighborResetOp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteNeighborRequest {
    pub asn: u32,
    pub addr: IpAddr,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequestV1 {
    /// ASN of the BGP router
    pub asn: u32,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponseV1 {
    pub by_peer: HashMap<IpAddr, MessageHistoryV1>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    Sent,
    Received,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
#[schemars(rename = "MessageHistoryRequest")]
pub struct MessageHistoryRequestV4 {
    /// ASN of the BGP router
    pub asn: u32,
    /// Optional peer filter - if None, returns history for all peers
    pub peer: Option<IpAddr>,
    /// Optional direction filter - if None, returns both sent and received
    pub direction: Option<MessageDirection>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
#[schemars(rename = "MessageHistoryResponse")]
pub struct MessageHistoryResponseV4 {
    pub by_peer: HashMap<IpAddr, MessageHistory>,
}

/// Unified message history request supporting both numbered and unnumbered peers
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,

    /// Optional peer filter using PeerId enum
    /// JSON format: {"ip": "192.0.2.1"} or {"interface": "eth0"}
    pub peer: Option<bgp::session::PeerId>,

    /// Optional direction filter - if None, returns both sent and received
    pub direction: Option<MessageDirection>,
}

/// Unified message history response with string keys from PeerId Display
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<String, MessageHistory>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FsmEventBuffer {
    /// All FSM events (high frequency, includes all timers)
    All,
    /// Major events only (state transitions, admin, new connections)
    Major,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
#[schemars(rename = "FsmHistoryRequest")]
pub struct FsmHistoryRequestV4 {
    /// ASN of the BGP router
    pub asn: u32,
    /// Optional peer filter - if None, returns history for all peers
    pub peer: Option<IpAddr>,
    /// Which buffer to retrieve - if None, returns major buffer
    pub buffer: Option<FsmEventBuffer>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
#[schemars(rename = "FsmHistoryResponse")]
pub struct FsmHistoryResponseV4 {
    /// Events organized by peer address Each peer's value contains only the events from the requested buffer
    pub by_peer: HashMap<IpAddr, Vec<FsmEventRecord>>,
}

/// Unified FSM history request supporting both numbered and unnumbered peers
#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct FsmHistoryRequest {
    /// ASN of the BGP router
    pub asn: u32,

    /// Optional peer filter using PeerId enum
    /// JSON format: {"ip": "192.0.2.1"} or {"interface": "eth0"}
    pub peer: Option<bgp::session::PeerId>,

    /// Which buffer to retrieve - if None, returns major buffer
    pub buffer: Option<FsmEventBuffer>,
}

/// Unified FSM history response with string keys from PeerId Display
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct FsmHistoryResponse {
    /// Events organized by peer identifier
    /// Each peer's value contains only the events from the requested buffer
    pub by_peer: HashMap<String, Vec<FsmEventRecord>>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BestpathFanoutRequest {
    /// Maximum number of equal-cost paths for ECMP forwarding
    pub fanout: NonZeroU8,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BestpathFanoutResponse {
    /// Current maximum number of equal-cost paths for ECMP forwarding
    pub fanout: NonZeroU8,
}

pub type GetRibResult = BTreeMap<String, BTreeSet<rdb::Path>>;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddStaticRoute4Request {
    pub routes: StaticRoute4List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteStaticRoute4Request {
    pub routes: StaticRoute4List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute4List {
    pub list: Vec<StaticRoute4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute4 {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

impl From<StaticRoute4> for StaticRouteKey {
    fn from(val: StaticRoute4) -> Self {
        StaticRouteKey {
            prefix: val.prefix.into(),
            nexthop: val.nexthop.into(),
            vlan_id: val.vlan_id,
            rib_priority: val.rib_priority,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddStaticRoute6Request {
    pub routes: StaticRoute6List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteStaticRoute6Request {
    pub routes: StaticRoute6List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute6List {
    pub list: Vec<StaticRoute6>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute6 {
    pub prefix: Prefix6,
    pub nexthop: Ipv6Addr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

impl From<StaticRoute6> for StaticRouteKey {
    fn from(val: StaticRoute6) -> Self {
        StaticRouteKey {
            prefix: val.prefix.into(),
            nexthop: val.nexthop.into(),
            vlan_id: val.vlan_id,
            rib_priority: val.rib_priority,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RibQuery {
    /// Filter by address family (None means all families)
    #[serde(default)]
    pub address_family: Option<AddressFamily>,
    /// Filter by protocol (optional)
    pub protocol: Option<ProtocolFilter>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(BTreeMap<String, BTreeSet<RdbPath>>);

impl From<rdb::db::Rib> for Rib {
    fn from(value: rdb::db::Rib) -> Self {
        Rib(value.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

pub fn filter_rib_by_protocol(
    rib: BTreeMap<Prefix, BTreeSet<RdbPath>>,
    protocol_filter: Option<ProtocolFilter>,
) -> BTreeMap<Prefix, BTreeSet<RdbPath>> {
    match protocol_filter {
        None => rib,
        Some(filter) => {
            let mut filtered = BTreeMap::new();

            for (prefix, paths) in rib {
                let filtered_paths: BTreeSet<RdbPath> = paths
                    .into_iter()
                    .filter(|path| match filter {
                        ProtocolFilter::Bgp => path.bgp.is_some(),
                        ProtocolFilter::Static => path.bgp.is_none(),
                    })
                    .collect();

                if !filtered_paths.is_empty() {
                    filtered.insert(prefix, filtered_paths);
                }
            }

            filtered
        }
    }
}

/// Selector for NDP interface queries
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpInterfaceSelector {
    /// ASN of the router
    pub asn: u32,
    /// Interface name
    pub interface: String,
}

/// NDP manager state showing overall health and interface status
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpManagerState {
    /// Whether the interface monitor thread is running
    pub monitor_thread_running: bool,
    /// Interfaces configured but not yet available on the system
    pub pending_interfaces: Vec<NdpPendingInterface>,
    /// Interfaces currently active in NDP (available on system)
    pub active_interfaces: Vec<String>,
}

/// Information about a pending NDP interface
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpPendingInterface {
    /// Interface name
    pub interface: String,
    /// Configured router lifetime (seconds)
    pub router_lifetime: u16,
}

/// Thread state for NDP rx/tx loops on an interface
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpThreadState {
    /// Whether the TX loop thread is running
    pub tx_running: bool,
    /// Whether the RX loop thread is running
    pub rx_running: bool,
}

/// NDP state for an interface
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpInterface {
    /// Interface name (e.g., "qsfp0")
    pub interface: String,
    /// Local IPv6 link-local address
    pub local_address: Ipv6Addr,
    /// IPv6 scope ID (interface index)
    pub scope_id: u32,
    /// Router lifetime advertised by this router (seconds)
    pub router_lifetime: u16,
    /// Information about discovered peer (if any, including expired)
    pub discovered_peer: Option<NdpPeer>,
    /// Thread state for rx/tx loops (None if interface not active in NDP)
    pub thread_state: Option<NdpThreadState>,
}

/// Information about a discovered NDP peer
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NdpPeer {
    /// Peer IPv6 address
    pub address: Ipv6Addr,
    /// When the peer was first discovered (ISO 8601 timestamp)
    pub discovered_at: String,
    /// When the most recent Router Advertisement was received (ISO 8601 timestamp)
    pub last_advertisement: String,
    /// Router lifetime from RA (seconds)
    pub router_lifetime: u16,
    /// Reachable time from RA (milliseconds)
    pub reachable_time: u32,
    /// Retransmit timer from RA (milliseconds)
    pub retrans_timer: u32,
    /// Whether the peer entry has expired
    pub expired: bool,
    /// Time until expiry (human-readable), or None if already expired
    pub time_until_expiry: Option<String>,
}
