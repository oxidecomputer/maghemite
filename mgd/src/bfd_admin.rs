// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use anyhow::Result;
use bfd_async::AddPeerError;
use bfd_async::Daemon;
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
/// address.
pub(crate) async fn get_bfd_peers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<BfdPeerInfo>>, HttpError> {
    let mut result = Vec::new();
    let daemon = lock!(ctx.context().bfd.daemon);
    for (addr, session) in daemon.sessions_iter() {
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

    Ok(HttpResponseOk(result))
}

/// Add a new peer to the daemon. A session for the specified peer will start
/// immediately.
pub(crate) async fn add_bfd_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<BfdPeerConfig>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    add_peer(ctx.context().clone(), request.into_inner())?;
    Ok(HttpResponseUpdatedNoContent())
}

pub(crate) fn add_peer(
    ctx: Arc<HandlerContext>,
    rq: BfdPeerConfig,
) -> Result<(), HttpError> {
    let mut daemon = lock!(ctx.bfd.daemon);
    daemon
        .add_peer(ctx.db.clone(), rq.into())
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
/// be stopped immediately.
pub(crate) async fn remove_bfd_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    params: Path<DeleteBfdPeerPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = params.into_inner();
    let listener_shutdown_handle = ctx
        .context()
        .bfd
        .daemon
        .lock()
        .unwrap()
        .remove_peer(rq.addr);

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

    Ok(HttpResponseUpdatedNoContent {})
}
