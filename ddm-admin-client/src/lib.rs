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

impl std::cmp::PartialEq for types::Vni {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl std::cmp::Eq for types::Vni {}

impl std::hash::Hash for types::Vni {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::cmp::PartialEq for types::MulticastOrigin {
    fn eq(&self, other: &Self) -> bool {
        self.overlay_group.eq(&other.overlay_group)
            && self.underlay_group.eq(&other.underlay_group)
            && self.vni.eq(&other.vni)
            && self.source.eq(&other.source)
    }
}

impl std::cmp::Eq for types::MulticastOrigin {}

/// Metric is excluded from identity so that metric changes update
/// an existing entry rather than creating a duplicate.
impl std::hash::Hash for types::MulticastOrigin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.overlay_group.hash(state);
        self.underlay_group.hash(state);
        self.vni.hash(state);
        self.source.hash(state);
    }
}
