// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types_versions::latest;
use ddm_api_types_versions::v1;
use ddm_api_types_versions::v2;
use ddm_api_types_versions::v3;
use ddm_api_types_versions::v4;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use dropshot_api_manager_types::api_versions;
use oxnet::Ipv6Net;
use std::collections::{HashMap, HashSet};

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
    (5, MULTICAST_SUPPORT),
    (4, OPENAPI_LINT),
    (3, EXTERNAL_PEERS),
    (2, PEER_DURATIONS),
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

    #[endpoint {
        method = GET,
        path = "/peers",
        versions = VERSION_MULTICAST_SUPPORT..,
    }]
    async fn get_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, latest::db::PeerInfo>>, HttpError>;

    #[endpoint {
        operation_id = "get_peers",
        method = GET,
        path = "/peers",
        versions = VERSION_OPENAPI_LINT..VERSION_MULTICAST_SUPPORT,
    }]
    async fn get_peers_v4(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, v4::db::PeerInfo>>, HttpError> {
        let resp = Self::get_peers(ctx).await?;
        let converted: HashMap<u32, v4::db::PeerInfo> =
            resp.0.into_iter().map(|(k, v)| (k, v.into())).collect();
        Ok(HttpResponseOk(converted))
    }

    #[endpoint {
        operation_id = "get_peers",
        method = GET,
        path = "/peers",
        versions = VERSION_PEER_DURATIONS..VERSION_OPENAPI_LINT,
    }]
    async fn get_peers_v2(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, v2::db::PeerInfo>>, HttpError> {
        let resp = Self::get_peers_v4(ctx).await?;
        let converted: HashMap<u32, v2::db::PeerInfo> =
            resp.0.into_iter().map(|(k, v)| (k, v.into())).collect();
        Ok(HttpResponseOk(converted))
    }

    #[endpoint {
        operation_id = "get_peers",
        method = GET,
        path = "/peers",
        versions = ..VERSION_PEER_DURATIONS,
    }]
    async fn get_peers_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, v1::db::PeerInfo>>, HttpError> {
        let resp = Self::get_peers_v2(ctx).await?;
        let converted: HashMap<u32, v1::db::PeerInfo> =
            resp.0.into_iter().map(|(k, v)| (k, v.into())).collect();
        Ok(HttpResponseOk(converted))
    }

    #[endpoint {
        method = DELETE,
        path = "/peers/{addr}",
    }]
    async fn expire_peer(
        ctx: RequestContext<Self::Context>,
        params: Path<latest::admin::ExpirePathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/originated",
    }]
    async fn get_originated(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<Ipv6Net>>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/originated-tunnel-endpoints",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn get_originated_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<latest::net::TunnelOrigin>>, HttpError>;

    #[endpoint {
        operation_id = "get_originated_tunnel_endpoints",
        method = GET,
        path = "/originated_tunnel_endpoints",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn get_originated_tunnel_endpoints_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v1::net::TunnelOrigin>>, HttpError> {
        Self::get_originated_tunnel_endpoints(ctx).await
    }

    #[endpoint {
        method = GET,
        path = "/prefixes",
    }]
    async fn get_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::admin::PrefixMap>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/tunnel-endpoints",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn get_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<latest::db::TunnelRoute>>, HttpError>;

    #[endpoint {
        operation_id = "get_tunnel_endpoints",
        method = GET,
        path = "/tunnel_endpoints",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn get_tunnel_endpoints_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v1::db::TunnelRoute>>, HttpError> {
        Self::get_tunnel_endpoints(ctx).await
    }

    #[endpoint {
        method = PUT,
        path = "/prefix",
    }]
    async fn advertise_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/tunnel-endpoint",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn advertise_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<latest::net::TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "advertise_tunnel_endpoints",
        method = PUT,
        path = "/tunnel_endpoint",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn advertise_tunnel_endpoints_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<v1::net::TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::advertise_tunnel_endpoints(ctx, request).await
    }

    #[endpoint {
        method = DELETE,
        path = "/prefix",
    }]
    async fn withdraw_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/tunnel-endpoint",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn withdraw_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<latest::net::TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "withdraw_tunnel_endpoints",
        method = DELETE,
        path = "/tunnel_endpoint",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn withdraw_tunnel_endpoints_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<v1::net::TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::withdraw_tunnel_endpoints(ctx, request).await
    }

    #[endpoint {
        method = GET,
        path = "/originated-multicast-groups",
        versions = VERSION_MULTICAST_SUPPORT..
    }]
    async fn get_originated_multicast_groups(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<latest::net::MulticastOrigin>>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/multicast-groups",
        versions = VERSION_MULTICAST_SUPPORT..
    }]
    async fn get_multicast_groups(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<latest::db::MulticastRoute>>, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/multicast-group",
        versions = VERSION_MULTICAST_SUPPORT..
    }]
    async fn advertise_multicast_groups(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<latest::net::MulticastOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = DELETE,
        path = "/multicast-group",
        versions = VERSION_MULTICAST_SUPPORT..
    }]
    async fn withdraw_multicast_groups(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<latest::net::MulticastOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/sync",
    }]
    async fn sync(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = POST,
        path = "/enable-stats",
    }]
    async fn enable_stats(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::admin::EnableStatsRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = POST,
        path = "/disable-stats",
    }]
    async fn disable_stats(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = PUT,
        path = "/external-peers",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn set_external_peers(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::external_peers::ExternalPeers>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "set_external_peers",
        method = PUT,
        path = "/external_peers",
        versions = VERSION_EXTERNAL_PEERS..VERSION_OPENAPI_LINT,
    }]
    async fn set_external_peers_v3(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v3::external_peers::ExternalPeers>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::set_external_peers(ctx, request).await
    }

    #[endpoint {
        method = GET,
        path = "/external-peers",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn get_external_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::external_peers::ExternalPeers>, HttpError>;

    #[endpoint {
        operation_id = "get_external_peers",
        method = GET,
        path = "/external_peers",
        versions = VERSION_EXTERNAL_PEERS..VERSION_OPENAPI_LINT,
    }]
    async fn get_external_peers_v3(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v3::external_peers::ExternalPeers>, HttpError>
    {
        Self::get_external_peers(ctx).await
    }
}
