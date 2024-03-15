// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use bgp::messages::Message;
pub use bgp::session::{MessageHistory, MessageHistoryEntry};
pub use rdb::{PolicyAction, Prefix4};

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
    replace = {
        Prefix4 = rdb::Prefix4,
        PolicyAction = rdb::PolicyAction,
        Message = bgp::messages::Message,
        MessageHistoryEntry = bgp::session::MessageHistoryEntry,
        MessageHistory = bgp::session::MessageHistory,
    }
);
