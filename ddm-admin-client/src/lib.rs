// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

progenitor::generate_api!(
    spec = "../openapi/ddm-admin/ddm-admin-latest.json",
    inner_type = slog::Logger,
    pre_hook = (|log: &slog::Logger, request: &reqwest::Request| {
        slog::trace!(log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    crates = {
        "oxnet" = "0.1.0",
    },
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::trace!(log, "client response"; "result" => ?result);
    }),
    replace = {
        TunnelOrigin = ddm_api_types_versions::latest::net::TunnelOrigin,
        MulticastOrigin = ddm_api_types_versions::latest::net::MulticastOrigin,
        UnderlayMulticastIpv6 = ddm_api_types_versions::latest::net::UnderlayMulticastIpv6,
        Vni = ddm_api_types_versions::latest::net::Vni,
        MulticastRoute = ddm_api_types_versions::latest::db::MulticastRoute,
        MulticastPathHop = ddm_api_types_versions::latest::exchange::MulticastPathHop,
        MulticastPathVector = ddm_api_types_versions::latest::exchange::MulticastPathVector,
        PeerInfo = ddm_api_types_versions::latest::db::PeerInfo,
        PeerStatus = ddm_api_types_versions::latest::db::PeerStatus,
        Duration = std::time::Duration,
    }
);
