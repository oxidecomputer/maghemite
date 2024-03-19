// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*
pub use bgp::messages::Message;
pub use bgp::session::{MessageHistory, MessageHistoryEntry};
pub use rdb::{PolicyAction, Prefix4};
*/

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
