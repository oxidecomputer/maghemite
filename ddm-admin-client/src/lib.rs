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
        PeerInfo = ddm_api_types_versions::latest::db::PeerInfo,
        PeerStatus = ddm_api_types_versions::latest::db::PeerStatus,
        Duration = std::time::Duration,
    }
);
