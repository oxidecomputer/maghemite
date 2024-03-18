// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use mg_common::net::IpPrefix;
pub use mg_common::net::Ipv4Prefix;
pub use mg_common::net::Ipv6Prefix;
pub use mg_common::net::TunnelOrigin;

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
           IpPrefix = mg_common::net::IpPrefix,
           Ipv4Prefix = mg_common::net::Ipv4Prefix,
           Ipv6Prefix = mg_common::net::Ipv6Prefix,
           TunnelOrigin = mg_common::net::TunnelOrigin,
       }
);
