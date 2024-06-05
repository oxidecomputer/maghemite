// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    crates = {
        "oxnet" = "0.1.0",
    },
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::trace!(log, "client response"; "result" => ?result);
    })
);

impl std::cmp::PartialEq for types::TunnelOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.overlay_prefix.eq(&other.overlay_prefix)
            && self.boundary_addr.eq(&other.boundary_addr)
            && self.vni.eq(&other.vni)
            && self.metric.eq(&other.metric)
    }
}

impl std::cmp::Eq for types::TunnelOrigin {}

impl std::hash::Hash for types::TunnelOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.overlay_prefix.hash(state);
        self.boundary_addr.hash(state);
        self.vni.hash(state);
        self.metric.hash(state);
    }
}
