// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, Ipv6Addr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bgp::router::SessionMap;
use dropshot::HttpServer;
use mg_admin_client::{Client, ClientInfo};
use mg_common::stats::MgLowerStats;
use rdb::test::{TestDb, get_test_db};
use slog::Logger;

use crate::{
    admin::HandlerContext, bfd_admin::BfdContext, bgp_admin::BgpContext,
};

/// A handler context that owns the guard for its test database.
///
/// Fields drop in declaration order, dropping the context before the
/// database directory is removed.
pub(crate) struct TestCtx {
    ctx: Arc<HandlerContext>,
    _db: TestDb,
}

impl Deref for TestCtx {
    type Target = Arc<HandlerContext>;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

/// Build a fresh handler context backed by an isolated on-disk test db.
pub(crate) fn test_ctx(name: &str) -> TestCtx {
    let (db, log) = test_db(name);

    let ctx = Arc::new(HandlerContext {
        #[cfg(all(feature = "mg-lower", target_os = "illumos"))]
        tep: Ipv6Addr::UNSPECIFIED,
        bgp: BgpContext::new(
            Arc::new(Mutex::new(SessionMap::new())),
            log.clone(),
        ),
        bfd: BfdContext::new(log.clone()),
        log: log.clone(),
        db: (*db).clone(),
        mg_lower_stats: Arc::new(MgLowerStats::default()),
        stats_server_running: Mutex::new(false),
        oximeter_port: 0,
    });
    TestCtx { ctx, _db: db }
}

/// Create an isolated test database and its file logger, both mapped to
/// `name`.
pub(crate) fn test_db(name: &str) -> (TestDb, Logger) {
    let log = mg_common::log::init_file_logger(&format!("{name}.log"));
    let db = get_test_db(name, log.clone()).expect("create db");
    (db, log)
}

/// An admin API server bound to loopback, with the client and the context it
/// serves.
pub(crate) struct TestServer {
    pub(crate) client: Client,
    server: HttpServer<Arc<HandlerContext>>,
    ctx: TestCtx,
}

impl TestServer {
    pub(crate) fn start(name: &str) -> Self {
        let ctx = test_ctx(name);
        let server = crate::admin::build_server(
            &ctx.log,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            0,
            Arc::clone(&ctx),
        )
        .expect("start admin server");
        let client = Client::new(
            &format!("http://{}", server.local_addr()),
            ctx.log.clone(),
        );
        Self {
            client,
            server,
            ctx,
        }
    }

    /// Close the server and then release the context and its test database.
    pub(crate) async fn shutdown(self) {
        let Self {
            client,
            server,
            ctx,
        } = self;
        drop(client);
        server.close().await.expect("close admin server");
        drop(ctx);
    }
}

/// Send a request outside the generated client and return the status code.
///
/// This reaches inputs the typed client cannot encode, such as an invalid
/// group in a query string.
pub(crate) async fn raw_status(
    client: &Client,
    method: http::Method,
    path_and_query: &str,
    body: Option<&str>,
) -> u16 {
    let mut req = client
        .client()
        .request(method, format!("{}{path_and_query}", client.baseurl()))
        .header(
            omicron_common::api::VERSION_HEADER,
            mg_api::latest_version().to_string(),
        );
    if let Some(body) = body {
        req = req
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
    }
    req.send().await.expect("send request").status().as_u16()
}

/// Return the HTTP status code carried by a client error, if any.
pub(crate) fn status<E>(err: &mg_admin_client::Error<E>) -> Option<u16> {
    err.status().map(|s| s.as_u16())
}
