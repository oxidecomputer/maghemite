// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use ddm::db::IpPrefix;
pub use ddm::db::Ipv4Prefix;
pub use ddm::db::Ipv6Prefix;
pub use ddm::db::TunnelOrigin;

progenitor::generate_api!(
    spec = "../openapi/ddm-admin.json",
    inner_type = slog::Logger,
    pre_hook = (|log: &slog::Logger, request: &reqwest::Request| {
        slog::trace!(log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::trace!(log, "client response"; "result" => ?result);
    }),
    replace = {
        IpPrefix = ddm::db::IpPrefix,
        Ipv4Prefix = ddm::db::Ipv4Prefix,
        Ipv6Prefix = ddm::db::Ipv6Prefix,
        TunnelOrigin = ddm::db::TunnelOrigin,
    }
);
