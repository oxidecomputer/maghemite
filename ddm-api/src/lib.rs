// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types_versions::{v1, v2, v3, v4, v5, v6};
use dropshot::{
    HttpError, HttpResponseOk, HttpResponseUpdatedNoContent, Path,
    RequestContext, TypedBody,
};
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
    (6, MULTIRACK),
    (5, PEER_STATS),
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

    /// Get the routing session on each address object, keyed by address
    /// object name, including sessions that have not discovered a peer.
    #[endpoint {
        method = GET,
        path = "/peers",
        versions = VERSION_PEER_STATS..,
    }]
    async fn get_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<String, v5::db::PeerInfo>>, HttpError>;

    #[endpoint {
        operation_id = "get_peers",
        method = GET,
        path = "/peers",
        versions = VERSION_OPENAPI_LINT..VERSION_PEER_STATS,
    }]
    async fn get_peers_v4(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, v4::db::PeerInfo>>, HttpError>;

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
        params: Path<v1::admin::ExpirePathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/originated",
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_originated(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v6::admin::OriginatedPrefix>>, HttpError>;

    #[endpoint {
        operation_id = "get_originated",
        method = GET,
        path = "/originated",
        versions = ..VERSION_MULTIRACK,
    }]
    async fn get_originated_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<Ipv6Net>>, HttpError> {
        // Before MULTIRACK, prefixes carried no kind.
        let resp = Self::get_originated(ctx).await?;
        Ok(HttpResponseOk(
            resp.0.into_iter().map(|p| p.prefix).collect(),
        ))
    }

    #[endpoint {
        method = GET,
        path = "/originated-tunnel-endpoints",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn get_originated_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v1::net::TunnelOrigin>>, HttpError>;

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
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v6::admin::PrefixMap>, HttpError>;

    #[endpoint {
        operation_id = "get_prefixes",
        method = GET,
        path = "/prefixes",
        versions = ..VERSION_MULTIRACK,
    }]
    async fn get_prefixes_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v1::admin::PrefixMap>, HttpError>;

    /// Get the tunnel routes imported from peers.
    ///
    /// Each route carries the path it was advertised along.
    #[endpoint {
        method = GET,
        path = "/tunnel-endpoints",
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v6::db::TunnelRoute>>, HttpError>;

    #[endpoint {
        operation_id = "get_tunnel_endpoints",
        method = GET,
        path = "/tunnel-endpoints",
        versions = VERSION_OPENAPI_LINT..VERSION_MULTIRACK,
    }]
    async fn get_tunnel_endpoints_v4(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v1::db::TunnelRoute>>, HttpError> {
        // Routes that differ only in their path become one route here.
        let resp = Self::get_tunnel_endpoints(ctx).await?;
        Ok(HttpResponseOk(resp.0.into_iter().map(Into::into).collect()))
    }

    #[endpoint {
        operation_id = "get_tunnel_endpoints",
        method = GET,
        path = "/tunnel_endpoints",
        versions = ..VERSION_OPENAPI_LINT,
    }]
    async fn get_tunnel_endpoints_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<v1::db::TunnelRoute>>, HttpError> {
        Self::get_tunnel_endpoints_v4(ctx).await
    }

    #[endpoint {
        method = PUT,
        path = "/prefix",
        versions = VERSION_MULTIRACK..,
    }]
    async fn advertise_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<v6::admin::OriginatedPrefix>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "advertise_prefixes",
        method = PUT,
        path = "/prefix",
        versions = ..VERSION_MULTIRACK,
    }]
    async fn advertise_prefixes_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        // Before MULTIRACK, every originated prefix was an underlay prefix.
        let request = request.map(|prefixes| {
            prefixes
                .into_iter()
                .map(|prefix| v6::admin::OriginatedPrefix {
                    kind: v6::admin::PrefixKind::Underlay,
                    prefix,
                })
                .collect()
        });
        Self::advertise_prefixes(ctx, request).await
    }

    #[endpoint {
        method = PUT,
        path = "/tunnel-endpoint",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn advertise_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<v1::net::TunnelOrigin>>,
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
        versions = VERSION_MULTIRACK..,
    }]
    async fn withdraw_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<v6::admin::OriginatedPrefix>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        operation_id = "withdraw_prefixes",
        method = DELETE,
        path = "/prefix",
        versions = ..VERSION_MULTIRACK,
    }]
    async fn withdraw_prefixes_v1(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        // Before MULTIRACK, every originated prefix was an underlay prefix.
        let request = request.map(|prefixes| {
            prefixes
                .into_iter()
                .map(|prefix| v6::admin::OriginatedPrefix {
                    kind: v6::admin::PrefixKind::Underlay,
                    prefix,
                })
                .collect()
        });
        Self::withdraw_prefixes(ctx, request).await
    }

    #[endpoint {
        method = DELETE,
        path = "/tunnel-endpoint",
        versions = VERSION_OPENAPI_LINT..,
    }]
    async fn withdraw_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<v1::net::TunnelOrigin>>,
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
        request: TypedBody<v1::admin::EnableStatsRequest>,
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
        request: TypedBody<v3::external_peers::ExternalPeers>,
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
    ) -> Result<HttpResponseOk<v3::external_peers::ExternalPeers>, HttpError>;

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

    /// Get the rack prefix this router originates.
    ///
    /// Returns 404 if none is set. Only supported on transit routers.
    #[endpoint {
        method = GET,
        path = "/rack-prefix",
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_rack_prefix(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v6::admin::RackPrefix>, HttpError>;

    /// Set the rack prefix this router originates.
    ///
    /// Replaces any previous rack prefix. Only supported on transit routers.
    #[endpoint {
        method = PUT,
        path = "/rack-prefix",
        versions = VERSION_MULTIRACK..,
    }]
    async fn set_rack_prefix(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v6::admin::RackPrefix>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Stop originating a rack prefix.
    ///
    /// Succeeds if none is set. Only supported on transit routers.
    #[endpoint {
        method = DELETE,
        path = "/rack-prefix",
        versions = VERSION_MULTIRACK..,
    }]
    async fn clear_rack_prefix(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the underlay address of this router.
    ///
    /// Returns 404 if none is set.
    #[endpoint {
        method = GET,
        path = "/underlay-address",
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_underlay_address(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<v6::admin::UnderlayAddress>, HttpError>;

    /// Set the underlay address of this router.
    ///
    /// Replaces any previous underlay address.
    #[endpoint {
        method = PUT,
        path = "/underlay-address",
        versions = VERSION_MULTIRACK..,
    }]
    async fn set_underlay_address(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<v6::admin::UnderlayAddress>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear the underlay address of this router.
    ///
    /// Succeeds if none is set.
    #[endpoint {
        method = DELETE,
        path = "/underlay-address",
        versions = VERSION_MULTIRACK..,
    }]
    async fn clear_underlay_address(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the counters of the routing session on each address object, keyed
    /// by address object name.
    #[endpoint {
        method = GET,
        path = "/stats/peers",
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_peers_stats(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<String, v6::db::PeerStats>>, HttpError>;

    /// Get the counters of the routing session on each address object, keyed
    /// by address object name.
    #[endpoint {
        operation_id = "get_peers_stats",
        method = GET,
        path = "/stats/peers",
        versions = VERSION_PEER_STATS..VERSION_MULTIRACK,
    }]
    async fn get_peers_stats_v5(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<String, v5::db::PeerStats>>, HttpError>
    {
        let resp = Self::get_peers_stats(ctx).await?;
        Ok(HttpResponseOk(
            resp.0.into_iter().map(|(k, v)| (k, v.into())).collect(),
        ))
    }

    /// Get the counters of the routing session on one address object.
    ///
    /// Address object names contain a `/` (e.g. `tfportqsfp0_0/v6`), which
    /// must be percent-encoded as `%2F` in the path. Returns 404 if no
    /// session uses the address object.
    #[endpoint {
        method = GET,
        path = "/stats/peer/{aobj_name}",
        versions = VERSION_MULTIRACK..,
    }]
    async fn get_peer_stats(
        ctx: RequestContext<Self::Context>,
        params: Path<v5::admin::PeerStatsPathParams>,
    ) -> Result<HttpResponseOk<v6::db::PeerStats>, HttpError>;

    /// Get the counters of the routing session on one address object.
    ///
    /// Address object names contain a `/` (e.g. `tfportqsfp0_0/v6`), which
    /// must be percent-encoded as `%2F` in the path. Returns 404 if no
    /// session uses the address object.
    #[endpoint {
        operation_id = "get_peer_stats",
        method = GET,
        path = "/stats/peer/{aobj_name}",
        versions = VERSION_PEER_STATS..VERSION_MULTIRACK,
    }]
    async fn get_peer_stats_v5(
        ctx: RequestContext<Self::Context>,
        params: Path<v5::admin::PeerStatsPathParams>,
    ) -> Result<HttpResponseOk<v5::db::PeerStats>, HttpError> {
        let resp = Self::get_peer_stats(ctx, params).await?;
        Ok(HttpResponseOk(resp.0.into()))
    }
}
