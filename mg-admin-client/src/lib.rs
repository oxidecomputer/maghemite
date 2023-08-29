pub use rdb::{PolicyAction, Prefix4};

progenitor::generate_api!(
    spec = "../openapi/mg-admin.json",
    inner_type = slog::Logger,
    pre_hook = (|log: &slog::Logger, request: &reqwest::Request| {
        slog::debug!(log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::debug!(log, "client response"; "result" => ?result);
    }),
    replace = {
        Prefix4 = rdb::Prefix4,
        PolicyAction = rdb::PolicyAction,
    }
);
