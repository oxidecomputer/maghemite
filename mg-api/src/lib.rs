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
    params::{
        ApplyRequest, CheckerSource, Neighbor, NeighborResetOp, Origin4,
        Origin6, PeerInfoV1, PeerInfoV2, Router, ShaperSource,
    },
    session::{MessageHistory, MessageHistoryV2},
};
use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, Query, RequestContext, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use rdb::{
    BfdPeerConfig, Path as RdbPath, Prefix, Prefix4, Prefix6, StaticRouteKey,
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

    #[endpoint { method = GET, path = "/bgp/config/neighbors" }]
    async fn read_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<Vec<Neighbor>>, HttpError>;

    #[endpoint { method = PUT, path = "/bgp/config/neighbor" }]
    async fn create_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/bgp/config/neighbor" }]
    async fn read_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<NeighborSelector>,
    ) -> Result<HttpResponseOk<Neighbor>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/config/neighbor" }]
    async fn update_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<Neighbor>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/bgp/config/neighbor" }]
    async fn delete_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: Query<NeighborSelector>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    #[endpoint { method = POST, path = "/bgp/clear/neighbor" }]
    async fn clear_neighbor(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<NeighborResetRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

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

    #[endpoint { method = GET, path = "/bgp/status/exported" }]
    async fn get_exported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, Vec<Prefix>>>, HttpError>;

    // imported moved under /rib/status in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/bgp/status/imported", versions = ..VERSION_IPV6_BASIC }]
    async fn get_imported(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<Rib>, HttpError>;

    // exported moved under /rib/status in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/bgp/status/selected", versions = ..VERSION_IPV6_BASIC }]
    async fn get_selected(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<AsnSelector>,
    ) -> Result<HttpResponseOk<Rib>, HttpError>;

    // imported moved under /rib/status in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/rib/status/imported", versions = VERSION_IPV6_BASIC.. }]
    async fn get_rib_imported(
        rqctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError>;

    // exported moved under /rib/status in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/rib/status/selected", versions = VERSION_IPV6_BASIC.. }]
    async fn get_rib_selected(
        rqctx: RequestContext<Self::Context>,
        request: Query<RibQuery>,
    ) -> Result<HttpResponseOk<Rib>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = ..VERSION_IPV6_BASIC }]
    async fn get_neighbors(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV1>>, HttpError>;

    #[endpoint { method = GET, path = "/bgp/status/neighbors", versions = VERSION_IPV6_BASIC.. }]
    async fn get_neighbors_v2(
        rqctx: RequestContext<Self::Context>,
        request: Query<AsnSelector>,
    ) -> Result<HttpResponseOk<HashMap<IpAddr, PeerInfoV2>>, HttpError>;

    #[endpoint { method = POST, path = "/bgp/omicron/apply" }]
    async fn bgp_apply(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<ApplyRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    // MessageHistory types updated in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/bgp/message-history", versions = ..VERSION_IPV6_BASIC }]
    async fn message_history(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError>;

    // MessageHistory types updated in VERSION_IPV6_BASIC
    #[endpoint { method = GET, path = "/bgp/message-history", versions = VERSION_IPV6_BASIC.. }]
    async fn message_history_v2(
        rqctx: RequestContext<Self::Context>,
        request: TypedBody<MessageHistoryRequest>,
    ) -> Result<HttpResponseOk<MessageHistoryResponseV2>, HttpError>;

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
pub struct DeleteRouterRequest {
    /// Autonomous system number for the router to remove
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborSelector {
    pub asn: u32,
    pub addr: IpAddr,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOp,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteNeighborRequest {
    pub asn: u32,
    pub addr: IpAddr,
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    pub asn: u32,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<IpAddr, MessageHistory>,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponseV2 {
    pub by_peer: HashMap<IpAddr, MessageHistoryV2>,
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
    /// Filter by address family
    #[serde(default)]
    pub address_family: AddressFamily,
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
