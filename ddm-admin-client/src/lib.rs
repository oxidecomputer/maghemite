// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

progenitor::generate_api!(
    spec = "../openapi/ddm-admin/ddm-admin-latest.json",
    inner_type = slog::Logger,
    hooks = Expected,
    crates = {
        "oxnet" = "0.1.0",
    },
    replace = {
        TunnelOrigin = ddm_api_types_versions::latest::net::TunnelOrigin,
        MulticastOrigin = ddm_api_types_versions::latest::net::MulticastOrigin,
        ExternalMulticastIp = ddm_api_types_versions::latest::net::OverlayMulticast,
        UnderlayMulticastIpv6 = ddm_api_types_versions::latest::net::UnderlayMulticastIpv6,
        MulticastRoute = ddm_api_types_versions::latest::db::MulticastRoute,
        MulticastPathHop = ddm_api_types_versions::latest::exchange::MulticastPathHop,
        PeerInfo = ddm_api_types_versions::latest::db::PeerInfo,
        PeerStatus = ddm_api_types_versions::latest::db::PeerStatus,
        Duration = std::time::Duration,
        ExternalPeers = ddm_api_types_versions::latest::external_peers::ExternalPeers,
    }
);

progenitor_extras::slog_hooks::impl_slog_client_hooks!(Client);
