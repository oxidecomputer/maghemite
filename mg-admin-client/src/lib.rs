// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

progenitor::generate_api!(
    spec = "../openapi/mg-admin.json",
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
    derives = [schemars::JsonSchema],
);

impl std::hash::Hash for types::Prefix4 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
        self.length.hash(state);
    }
}

impl std::cmp::PartialEq for types::Prefix4 {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value) && self.length.eq(&other.length)
    }
}

impl std::cmp::Eq for types::Prefix4 {}

impl Copy for types::Prefix4 {}

impl std::str::FromStr for types::Prefix4 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (value, length) =
            s.split_once('/').ok_or("malformed route key".to_string())?;

        Ok(Self {
            value: value
                .parse()
                .map_err(|_| "malformed ip addr".to_string())?,
            length: length
                .parse()
                .map_err(|_| "malformed length".to_string())?,
        })
    }
}

impl types::Prefix4 {
    pub fn new(ip: std::net::Ipv4Addr, length: u8) -> Self {
        Self {
            value: mg_common::net::zero_host_bits_v4(ip, length),
            length,
        }
    }
}

impl types::Prefix6 {
    pub fn new(ip: std::net::Ipv6Addr, length: u8) -> Self {
        Self {
            value: mg_common::net::zero_host_bits_v6(ip, length),
            length,
        }
    }
}
