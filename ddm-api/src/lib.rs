// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types_versions::latest;
use ddm_api_types_versions::v1;
use ddm_api_types_versions::v2;
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
    (4, RACK_PREFIXES),
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
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn get_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<String, latest::db::PeerInfo>>, HttpError>;

    // Required rather than provided: older versions key sessions by interface
    // index, which the latest response does not carry, so the server builds
    // this from its live session table.
    #[endpoint {
        method = GET,
        path = "/peers",
        operation_id = "get_peers",
        versions = VERSION_PEER_DURATIONS..VERSION_RACK_PREFIXES,
    }]
    async fn get_peers_v2(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, v2::db::PeerInfo>>, HttpError>;

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
        path = "/originated_tunnel_endpoints",
    }]
    async fn get_originated_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<latest::net::TunnelOrigin>>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/prefixes",
    }]
    async fn get_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::admin::PrefixMap>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/tunnel_endpoints",
    }]
    async fn get_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<latest::db::TunnelRoute>>, HttpError>;

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
        path = "/tunnel_endpoint",
    }]
    async fn advertise_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<latest::net::TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

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
        path = "/tunnel_endpoint",
    }]
    async fn withdraw_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<latest::net::TunnelOrigin>>,
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
        path = "/external_peers",
        versions = VERSION_EXTERNAL_PEERS..,
    }]
    async fn set_external_peers(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<latest::external_peers::ExternalPeers>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    #[endpoint {
        method = GET,
        path = "/external_peers",
        versions = VERSION_EXTERNAL_PEERS..,
    }]
    async fn get_external_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::external_peers::ExternalPeers>, HttpError>;

    /// Get the rack prefixes originated by this router. Only supported on
    /// transit routers.
    #[endpoint {
        method = GET,
        path = "/originated_rack_prefixes",
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn get_originated_rack_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<HashMap<Ipv6Net, latest::net::RackPrefixInfo>>,
        HttpError,
    >;

    /// Originate rack prefixes from this router, each with an optional
    /// multi-rack join address. The body is keyed by prefix so a prefix
    /// carries at most one join address. Advertising a prefix again replaces
    /// its join address. Originated prefixes not in the body are left
    /// unchanged. Only supported on transit routers.
    #[endpoint {
        method = PUT,
        path = "/originated_rack_prefixes",
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn advertise_rack_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashMap<Ipv6Net, latest::net::RackPrefixInfo>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Withdraw rack prefixes originated by this router. Only supported on
    /// transit routers.
    #[endpoint {
        method = DELETE,
        path = "/originated_rack_prefixes",
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn withdraw_rack_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the rack prefixes this router has learned from its peers, with the
    /// distinct info carried by their paths, including paths that carry no
    /// multi-rack join address.
    #[endpoint {
        method = GET,
        path = "/rack_prefixes",
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn get_rack_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<HashMap<Ipv6Net, HashSet<latest::net::RackPrefixInfo>>>,
        HttpError,
    >;

    /// Get the counters of the routing session on each address object, keyed
    /// by address object name.
    #[endpoint {
        method = GET,
        path = "/stats/peers",
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn get_peers_stats(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<String, latest::db::PeerStats>>, HttpError>;

    /// Get the counters of the routing session on one address object.
    ///
    /// Address object names contain a `/` (e.g. `tfportqsfp0_0/v6`), which
    /// must be percent-encoded as `%2F` in the path. Returns 404 if no
    /// session uses the address object.
    #[endpoint {
        method = GET,
        path = "/stats/peer/{aobj_name}",
        versions = VERSION_RACK_PREFIXES..,
    }]
    async fn get_peer_stats(
        ctx: RequestContext<Self::Context>,
        params: Path<latest::admin::PeerStatsPathParams>,
    ) -> Result<HttpResponseOk<latest::db::PeerStats>, HttpError>;
}
