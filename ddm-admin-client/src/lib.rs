// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

progenitor::generate_api!(
    spec = "../openapi/ddm-admin/ddm-admin-latest.json",
    inner_type = slog::Logger,
    hooks = Expected,
    crates = {
        "oxnet" = "0.1.0",
        "std" = "1.0.0",
    },
    replace = {
        TunnelOrigin = ddm_api_types_versions::latest::net::TunnelOrigin,
        RackPrefixInfo = ddm_api_types_versions::latest::net::RackPrefixInfo,
        Peer = ddm_api_types_versions::latest::db::Peer,
        PeerInfo = ddm_api_types_versions::latest::db::PeerInfo,
        PeerStats = ddm_api_types_versions::latest::db::PeerStats,
        PeerStatus = ddm_api_types_versions::latest::db::PeerStatus,
        Duration = std::time::Duration,
        ExternalPeers = ddm_api_types_versions::latest::external_peers::ExternalPeers,
    }
);

progenitor_extras::slog_hooks::impl_slog_client_hooks!(Client);
