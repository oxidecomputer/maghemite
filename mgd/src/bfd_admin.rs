// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use anyhow::Result;
use bfd::AddPeerError;
use bfd::Daemon;
use dropshot::{
    ClientErrorStatusCode, HttpError, HttpResponseOk,
    HttpResponseUpdatedNoContent, Path, RequestContext, TypedBody,
};
use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bfd::BfdPeerInfo;
use mg_api_types::bfd::DeleteBfdPeerPathParams;
use mg_common::lock;
use slog::Logger;
use slog_error_chain::InlineErrorChain;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Context for Dropshot requests.
#[derive(Clone)]
pub struct BfdContext {
    /// The underlying deamon being run.
    pub(crate) daemon: Arc<Mutex<Daemon>>,
}

impl BfdContext {
    pub fn new(log: Logger) -> Self {
        Self {
            daemon: Arc::new(Mutex::new(Daemon::new(log.clone()))),
        }
    }
}

/// Get all the peers and their associated BFD state. Peers are identified by IP
/// address. As a legacy endpoint, it only sees the default router's peers.
pub(crate) async fn get_bfd_peers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<BfdPeerInfo>>, HttpError> {
    let ctx = ctx.context();
    let router_db = ctx.default_router()?;
    Ok(HttpResponseOk(get_peers(ctx, &router_db)?))
}

pub(crate) fn get_peers(
    ctx: &HandlerContext,
    router_db: &rdb::RouterDb,
) -> Result<Vec<BfdPeerInfo>, HttpError> {
    let mut result = Vec::new();
    let daemon = lock!(ctx.bfd.daemon);
    for (addr, session) in daemon.sessions_iter() {
        if session.router() != router_db.id() {
            continue;
        }
        result.push(BfdPeerInfo {
            config: BfdPeerConfig {
                peer: *addr,
                required_rx: session.required_rx_micros(),
                detection_threshold: session.detection_threshold(),
                listen: daemon
                    .listen_addr_for_peer(addr)
                    .ok_or(HttpError::for_internal_error(format!(
                        "no listener for {addr}"
                    )))?
                    .ip(),
                mode: session.mode(),
            },
            state: session.state(),
        });
    }

    Ok(result)
}

/// Add a new peer to the daemon. A session for the specified peer will start
/// immediately.
pub(crate) async fn add_bfd_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<BfdPeerConfig>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let router_db = ctx.default_router()?;
    add_peer(ctx.clone(), router_db, request.into_inner())?;
    Ok(HttpResponseUpdatedNoContent())
}

pub(crate) fn add_peer(
    ctx: Arc<HandlerContext>,
    router_db: rdb::RouterDb,
    rq: BfdPeerConfig,
) -> Result<(), HttpError> {
    let mut daemon = lock!(ctx.bfd.daemon);
    daemon
        .add_peer(router_db, rq.into())
        .map_err(|err| match err {
            AddPeerError::PeerExists(_) => HttpError::for_client_error(
                None,
                ClientErrorStatusCode::CONFLICT,
                InlineErrorChain::new(&err).to_string(),
            ),
            AddPeerError::Bind { .. }
            | AddPeerError::SetSocketNonBlocking(_)
            | AddPeerError::StdToTokio(_) => HttpError::for_internal_error(
                InlineErrorChain::new(&err).to_string(),
            ),
        })
}

/// Remove the specified peer from the daemon. The associated peer session will
/// be stopped immediately. As a legacy endpoint, it only removes peers from the
/// default router.
pub(crate) async fn remove_bfd_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    params: Path<DeleteBfdPeerPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let router_db = ctx.default_router()?;
    remove_peer(ctx, &router_db, params.into_inner().addr).await;
    Ok(HttpResponseUpdatedNoContent {})
}

pub(crate) async fn remove_peer(
    ctx: &HandlerContext,
    router_db: &rdb::RouterDb,
    addr: IpAddr,
) {
    let listener_shutdown_handle = {
        let mut daemon = lock!(ctx.bfd.daemon);
        match daemon.session(&addr) {
            Some(session) if session.router() == router_db.id() => {
                daemon.remove_peer(addr)
            }
            _ => None,
        }
    };

    if let Some(handle) = listener_shutdown_handle {
        // If this was the last peer associated with a given local listening
        // address, wait for the listening socket to be closed (allowing a
        // caller to add a new peer at the same listening address once this
        // returns).
        //
        // We've already unlocked the `bfd.daemon`, so it's possible a
        // _concurrent_ request for the same listen address we're shutting down
        // here could fail, but that's inherently racy: we can only guarantee
        // that a client waiting for this remove to complete is able to add a
        // new peer at the same listening address.
        handle.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{add_peer, get_peers, remove_peer};
    use crate::admin::test::test_ctx;
    use mg_api_types::bfd::{BfdPeerConfig, SessionMode};
    use mg_common::lock;
    use rdb::types::{RouterId, RouterInfo};
    use std::net::{IpAddr, Ipv6Addr};
    use std::num::NonZeroU8;

    /// The legacy endpoints only operate on the default router.
    #[tokio::test]
    async fn legacy_endpoints_only_operate_on_the_default_router() {
        let ctx =
            test_ctx("legacy_endpoints_only_operate_on_the_default_router");
        let default = ctx.default_router().unwrap();
        let other = ctx
            .db
            .create_router(RouterInfo {
                id: RouterId::new_random(),
                name: "other".into(),
                tep: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            })
            .unwrap();
        let addr: IpAddr = "203.0.113.1".parse().unwrap();
        // Multihop listens on its own port, apart from the other tests' peers.
        let peer = BfdPeerConfig {
            peer: addr,
            listen: "127.0.0.1".parse().unwrap(),
            required_rx: 1_000_000,
            detection_threshold: NonZeroU8::new(3).unwrap(),
            mode: SessionMode::MultiHop,
        };
        add_peer(ctx.clone(), other, peer).unwrap();

        assert!(get_peers(&ctx, &default).unwrap().is_empty());
        remove_peer(&ctx, &default, addr).await;
        assert!(lock!(ctx.bfd.daemon).session(&addr).is_some());
    }
}
