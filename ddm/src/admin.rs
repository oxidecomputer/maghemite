// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::db::Db;
use crate::sm::{AdminEvent, Event, PrefixSet, SmContext};
use ddm_api::DdmAdminApi;
use ddm_api::ddm_admin_api_mod;
use ddm_types::admin::{
    EnableStatsRequest, ExpirePathParams, PrefixMap, PutPeerRequest,
};
use ddm_types::db::{MulticastRoute, PeerInfo, TunnelRoute};
use ddm_types::exchange::PathVector;
use dropshot::ApiDescription;
use dropshot::ApiDescriptionBuildErrors;
use dropshot::ConfigDropshot;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use mg_common::lock;
use mg_common::net::{MulticastOrigin, TunnelOrigin};
use oxnet::Ipv6Net;
use slog::{Logger, error, info, o};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use tokio::spawn;
use tokio::task::JoinHandle;

pub const DDM_STATS_PORT: u16 = 8001;

const UNIT_API_SERVER: &str = "api_server";

#[derive(Default)]
pub struct RouterStats {
    pub originated_underlay_prefixes: AtomicU64,
    pub originated_tunnel_endpoints: AtomicU64,
}

#[derive(Clone)]
pub struct HandlerContext {
    pub event_channels: Vec<Sender<Event>>,
    pub db: Db,
    pub stats: Arc<RouterStats>,
    pub peers: Vec<SmContext>,
    pub stats_handler: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub log: Logger,
}

pub fn handler(
    addr: IpAddr,
    port: u16,
    context: Arc<Mutex<HandlerContext>>,
    log: Logger,
) -> Result<(), String> {
    let sa: SocketAddr = match addr {
        IpAddr::V4(a) => SocketAddrV4::new(a, port).into(),
        IpAddr::V6(a) => SocketAddrV6::new(a, port, 0, 0).into(),
    };

    let config = ConfigDropshot {
        bind_address: sa,
        default_request_body_max_bytes: 1024 * 1024 * 1024,
        ..Default::default()
    };

    let ds_log = log.new(o!(
        "component" => crate::COMPONENT_DDM,
        "module" => crate::MOD_ADMIN,
        "unit" => UNIT_API_SERVER,
    ));

    let api = api_description().map_err(|e| e.to_string())?;

    let server = dropshot::ServerBuilder::new(api, context, ds_log)
        .config(config)
        .version_policy(dropshot::VersionPolicy::Dynamic(Box::new(
            dropshot::ClientSpecifiesVersionInHeader::new(
                omicron_common::api::VERSION_HEADER,
                ddm_api::latest_version(),
            ),
        )));

    info!(log, "admin: listening on {}", sa);

    let log = log.clone();
    spawn(async move {
        match server.start() {
            Ok(server) => {
                info!(log, "admin: server started");
                match server.await {
                    Ok(()) => info!(log, "admin: server exited"),
                    Err(e) => error!(log, "admin: server error {:?}", e),
                }
            }
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    });

    Ok(())
}

pub enum DdmAdminApiImpl {}

impl DdmAdminApi for DdmAdminApiImpl {
    type Context = Arc<Mutex<HandlerContext>>;

    async fn get_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashMap<u32, PeerInfo>>, HttpError> {
        Ok(HttpResponseOk(do_get_peers(ctx.context())))
    }

    async fn get_peers_v1(
        ctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<HashMap<u32, ddm_types_versions::v1::db::PeerInfo>>,
        HttpError,
    > {
        let ctx = lock!(ctx.context());
        let peers = ctx
            .db
            .peers()
            .into_iter()
            .map(|(k, v)| (k, v.into()))
            .collect();
        Ok(HttpResponseOk(peers))
    }

    async fn expire_peer(
        ctx: RequestContext<Self::Context>,
        params: Path<ExpirePathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let addr = params.into_inner().addr;
        let ctx = lock!(ctx.context());

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Expire(addr)))
                .map_err(|e| {
                    HttpError::for_internal_error(format!(
                        "admin event send: {e}"
                    ))
                })?;
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn put_peer(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<PutPeerRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        do_put_peer(ctx.context(), request.into_inner());
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn get_originated(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<Ipv6Net>>, HttpError> {
        let ctx = lock!(ctx.context());
        let originated = ctx
            .db
            .originated()
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
        Ok(HttpResponseOk(originated))
    }

    async fn get_originated_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<TunnelOrigin>>, HttpError> {
        let ctx = lock!(ctx.context());
        let originated = ctx
            .db
            .originated_tunnel()
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
        Ok(HttpResponseOk(originated))
    }

    async fn get_prefixes(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<PrefixMap>, HttpError> {
        let ctx = lock!(ctx.context());
        let imported = ctx.db.imported();

        let mut result = PrefixMap::default();

        for route in imported {
            if let Some(entry) = result.get_mut(&route.nexthop) {
                entry.insert(PathVector {
                    destination: route.destination,
                    path: route.path,
                });
            } else {
                let mut s = HashSet::new();
                s.insert(PathVector {
                    destination: route.destination,
                    path: route.path,
                });
                result.insert(route.nexthop, s);
            }
        }

        Ok(HttpResponseOk(result))
    }

    async fn get_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<TunnelRoute>>, HttpError> {
        let ctx = lock!(ctx.context());
        let imported = ctx.db.imported_tunnel();
        Ok(HttpResponseOk(imported))
    }

    async fn advertise_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let prefixes = request.into_inner();
        ctx.db
            .originate(&prefixes)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Announce(PrefixSet::Underlay(
                prefixes.clone(),
            ))))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        match ctx.db.originated_count() {
            Ok(count) => ctx
                .stats
                .originated_underlay_prefixes
                .store(count as u64, Ordering::Relaxed),
            Err(e) => {
                error!(
                    ctx.log,
                    "failed to update originated underlay prefixes stat: {e}"
                )
            }
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn advertise_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let endpoints = request.into_inner();
        slog::info!(ctx.log, "advertise tunnel: {:#?}", endpoints);
        ctx.db
            .originate_tunnel(&endpoints)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Announce(PrefixSet::Tunnel(
                endpoints.clone(),
            ))))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        match ctx.db.originated_tunnel_count() {
            Ok(count) => ctx
                .stats
                .originated_tunnel_endpoints
                .store(count as u64, Ordering::Relaxed),
            Err(e) => {
                error!(
                    ctx.log,
                    "failed to update originated tunnel endpoints stat: {e}"
                )
            }
        }
        Ok(HttpResponseUpdatedNoContent())
    }

    async fn withdraw_prefixes(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<Ipv6Net>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let prefixes = request.into_inner();
        ctx.db
            .withdraw(&prefixes)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Withdraw(PrefixSet::Underlay(
                prefixes.clone(),
            ))))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        match ctx.db.originated_count() {
            Ok(count) => ctx
                .stats
                .originated_underlay_prefixes
                .store(count as u64, Ordering::Relaxed),
            Err(e) => {
                error!(
                    ctx.log,
                    "failed to update originated underlay prefixes stat: {e}"
                )
            }
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn withdraw_tunnel_endpoints(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<TunnelOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let endpoints = request.into_inner();
        slog::info!(ctx.log, "withdraw tunnel: {:#?}", endpoints);
        ctx.db
            .withdraw_tunnel(&endpoints)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Withdraw(PrefixSet::Tunnel(
                endpoints.clone(),
            ))))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        match ctx.db.originated_tunnel_count() {
            Ok(count) => ctx
                .stats
                .originated_tunnel_endpoints
                .store(count as u64, Ordering::Relaxed),
            Err(e) => {
                error!(
                    ctx.log,
                    "failed to update originated tunel endpoints stat: {e}"
                )
            }
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn get_originated_multicast_groups(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<MulticastOrigin>>, HttpError> {
        let ctx = lock!(ctx.context());
        let originated = ctx
            .db
            .originated_mcast()
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
        Ok(HttpResponseOk(originated))
    }

    async fn get_multicast_groups(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<HashSet<MulticastRoute>>, HttpError> {
        let ctx = lock!(ctx.context());
        let imported = ctx.db.imported_mcast();
        Ok(HttpResponseOk(imported))
    }

    async fn advertise_multicast_groups(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<MulticastOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let groups = request.into_inner();
        slog::info!(ctx.log, "advertise multicast groups: {groups:#?}");
        ctx.db
            .originate_mcast(&groups)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Announce(PrefixSet::Multicast(
                groups.clone(),
            ))))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn withdraw_multicast_groups(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<HashSet<MulticastOrigin>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let groups = request.into_inner();
        slog::info!(ctx.log, "withdraw multicast groups: {groups:#?}");
        ctx.db
            .withdraw_mcast(&groups)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Withdraw(PrefixSet::Multicast(
                groups.clone(),
            ))))
            .map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn sync(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());

        for e in &ctx.event_channels {
            e.send(Event::Admin(AdminEvent::Sync)).map_err(|e| {
                HttpError::for_internal_error(format!("admin event send: {e}"))
            })?;
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn enable_stats(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<EnableStatsRequest>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let rq = request.into_inner();
        let ctx = lock!(ctx.context());

        let mut jh = lock!(ctx.stats_handler);
        if jh.is_none() {
            let hostname = hostname::get()
                .expect("failed to get hostname")
                .to_string_lossy()
                .to_string();
            *jh = Some(
                crate::oxstats::start_server(
                    DDM_STATS_PORT,
                    ctx.peers.clone(),
                    ctx.stats.clone(),
                    hostname,
                    rq.rack_id,
                    rq.sled_id,
                    ctx.log.clone(),
                )
                .map_err(|e| {
                    HttpError::for_internal_error(format!(
                        "failed to start stats server: {e}"
                    ))
                })?,
            );
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn disable_stats(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());
        let mut jh = lock!(ctx.stats_handler);
        if let Some(ref h) = *jh {
            h.abort();
        }
        *jh = None;

        Ok(HttpResponseUpdatedNoContent())
    }
}

pub fn api_description()
-> Result<ApiDescription<Arc<Mutex<HandlerContext>>>, ApiDescriptionBuildErrors>
{
    ddm_admin_api_mod::api_description::<DdmAdminApiImpl>()
}

/// Snapshot the current peer table, keyed by interface index.
pub(crate) fn do_get_peers(
    ctx: &Arc<Mutex<HandlerContext>>,
) -> HashMap<u32, PeerInfo> {
    let ctx = lock!(ctx);
    ctx.db.peers()
}

/// Insert or replace the peer entry at `request.if_index`. Tests bypass
/// the dropshot endpoint and call this directly; production goes through
/// [`DdmAdminApiImpl::put_peer`].
pub(crate) fn do_put_peer(
    ctx: &Arc<Mutex<HandlerContext>>,
    request: PutPeerRequest,
) {
    let PutPeerRequest { if_index, info } = request;
    let ctx = lock!(ctx);
    ctx.db.set_peer(if_index, info);
}

#[cfg(test)]
mod tests {
    use super::{HandlerContext, RouterStats, do_get_peers, do_put_peer};
    use crate::db::Db;
    use ddm_types::admin::PutPeerRequest;
    use ddm_types::db::{PeerInfo, PeerStatus, RouterKind};
    use slog::{Discard, Logger, o};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn build_context(tmpdir: &TempDir) -> Arc<Mutex<HandlerContext>> {
        let log = Logger::root(Discard, o!());
        let db_path = tmpdir.path().join("ddm").to_str().unwrap().to_string();
        let db = Db::new(&db_path, log.clone()).expect("open db");
        Arc::new(Mutex::new(HandlerContext {
            event_channels: vec![],
            db,
            stats: Arc::new(RouterStats::default()),
            peers: vec![],
            stats_handler: Arc::new(Mutex::new(None)),
            log,
        }))
    }

    #[test]
    fn put_peer_round_trips() {
        let tmpdir = TempDir::new().expect("tempdir");
        let ctx = build_context(&tmpdir);

        let info = PeerInfo {
            status: PeerStatus::Active,
            addr: "fd00::1".parse().unwrap(),
            host: "test-sled-1".to_string(),
            kind: RouterKind::Server,
            if_name: Some("tfportrear0_0".to_string()),
        };

        do_put_peer(
            &ctx,
            PutPeerRequest {
                if_index: 7,
                info: info.clone(),
            },
        );

        let peers = do_get_peers(&ctx);
        assert_eq!(peers.len(), 1);
        let got = peers.get(&7).expect("peer at if_index 7");
        assert_eq!(got, &info);

        // Overwriting at the same `if_index` replaces the entry rather
        // than creating a second one.
        let info2 = PeerInfo {
            addr: "fd00::2".parse().unwrap(),
            host: "test-sled-1-replaced".to_string(),
            ..info
        };
        do_put_peer(
            &ctx,
            PutPeerRequest {
                if_index: 7,
                info: info2.clone(),
            },
        );
        let peers = do_get_peers(&ctx);
        assert_eq!(peers.len(), 1, "overwrite at same if_index keeps map size",);
        assert_eq!(peers[&7].addr, info2.addr);
    }
}
