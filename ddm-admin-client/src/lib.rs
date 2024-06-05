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
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::trace!(log, "client response"; "result" => ?result);
    })
);

impl Copy for types::Ipv4Net {}
impl Copy for types::Ipv6Net {}
impl Copy for types::IpNet {}

impl std::cmp::PartialEq for types::Ipv4Net {
    fn eq(&self, other: &Self) -> bool {
        self.addr.eq(&other.addr) && self.len.eq(&other.len)
    }
}

impl std::cmp::Eq for types::Ipv4Net {}

impl std::hash::Hash for types::Ipv4Net {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.len.hash(state);
    }
}

impl std::cmp::PartialEq for types::Ipv6Net {
    fn eq(&self, other: &Self) -> bool {
        self.addr.eq(&other.addr) && self.len.eq(&other.len)
    }
}

impl std::cmp::Eq for types::Ipv6Net {}

impl std::hash::Hash for types::Ipv6Net {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.len.hash(state);
    }
}

impl std::cmp::PartialEq for types::IpNet {
    fn eq(&self, other: &Self) -> bool {
        match self {
            types::IpNet::V4(x) => match other {
                types::IpNet::V4(y) => x.eq(y),
                _ => false,
            },
            types::IpNet::V6(x) => match other {
                types::IpNet::V6(y) => x.eq(y),
                _ => false,
            },
        }
    }
}

impl std::hash::Hash for types::IpNet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            types::IpNet::V4(x) => x.hash(state),
            types::IpNet::V6(x) => x.hash(state),
        }
    }
}

impl std::cmp::Eq for types::IpNet {}

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
