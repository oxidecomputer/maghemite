// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_types::db::PeerInfo;
use ddm_types::db::TunnelRoute;
use ddm_types::exchange::PathVector;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use dropshot_api_manager_types::api_versions;
use mg_common::net::TunnelOrigin;
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv6Addr;
use uuid::Uuid;

pub type PrefixMap = BTreeMap<Ipv6Addr, HashSet<PathVector>>;

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
pub trait DdmAdminApi {
    type Context;

    #[endpoint { method = GET, path = "/peers" }]
    async fn get_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, PeerInfo>>, HttpError>;

    #[endpoint { method = DELETE, path = "/peers/{addr}" }]
    async fn expire_peer(
        ctx: RequestContext<Self::Context>,
        params: Path<ExpirePathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = GET, path = "/originated" }]
    async fn get_originated(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<Ipv6Net>>, HttpError>;

    #[endpoint { method = GET, path = "/originated_tunnel_endpoints" }]
    async fn get_originated_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<TunnelOrigin>>, HttpError>;

    #[endpoint { method = GET, path = "/prefixes" }]
    async fn get_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<PrefixMap>, HttpError>;

    #[endpoint { method = GET, path = "/tunnel_endpoints" }]
    async fn get_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<TunnelRoute>>, HttpError>;

    #[endpoint { method = PUT, path = "/prefix" }]
    async fn advertise_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = PUT, path = "/tunnel_endpoint" }]
    async fn advertise_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/prefix" }]
    async fn withdraw_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = DELETE, path = "/tunnel_endpoint" }]
    async fn withdraw_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = PUT, path = "/sync" }]
    async fn sync(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = POST, path = "/enable-stats" }]
    async fn enable_stats(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<EnableStatsRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint { method = POST, path = "/disable-stats" }]
    async fn disable_stats(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ExpirePathParams {
    pub addr: Ipv6Addr,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EnableStatsRequest {
    pub sled_id: Uuid,
    pub rack_id: Uuid,
}
