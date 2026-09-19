// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::db::Db;
use crate::defaults::{
    DISCOVERY_READ_TIMEOUT, EXCHANGE_TCP_PORT, EXCHANGE_TIMEOUT,
    EXPIRE_THRESHOLD, IP_ADDR_WAIT, SOLICIT_INTERVAL,
};
use crate::sm::{
    AdminEvent, Event, InterfaceState, PrefixSet, SessionStats, SmContext,
    StateMachine,
};
use camino::Utf8PathBuf;
use ddm_api::DdmAdminApi;
use ddm_api::ddm_admin_api_mod;
use ddm_api_types::admin::{EnableStatsRequest, ExpirePathParams, PrefixMap};
use ddm_api_types::db::{PeerInfo, RouterKind, TunnelRoute};
use ddm_api_types::exchange::PathVector;
use ddm_api_types::external_peers::ExternalPeers;
use ddm_api_types::net::TunnelOrigin;
use dropshot::ApiDescription;
use dropshot::ApiDescriptionBuildErrors;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use mg_common::lock;
use oxnet::Ipv6Net;
use slog::{Logger, debug, error, info, o};
use slog_error_chain::InlineErrorChain;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;
use tokio::spawn;
use tokio::task::JoinHandle;
use uuid::Uuid;

pub const DDM_STATS_PORT: u16 = 8001;

const UNIT_API_SERVER: &str = "api_server";

#[derive(Default)]
pub struct RouterStats {
    pub originated_underlay_prefixes: AtomicU64,
    pub originated_tunnel_endpoints: AtomicU64,
}

#[derive(Clone)]
pub struct HandlerContext {
    pub db: Db,
    pub stats: Arc<RouterStats>,
    pub peers: Vec<SmContext>,
    pub stats_handler: Arc<Mutex<Option<JoinHandle<()>>>>,
    pub tunables: Tunables,
    pub router_kind: RouterKind,
    pub rack_id: Option<Uuid>,
    pub sled_id: Option<Uuid>,
    pub router_id: String,
    pub log: Logger,
}

impl HandlerContext {
    pub fn event_channels(&self) -> impl Iterator<Item = &Sender<Event>> {
        self.peers.iter().map(|x| &x.tx)
    }
}

#[derive(Clone)]
pub struct Tunables {
    pub solicit_interval: Duration,
    pub expire_threshold: Duration,
    pub discovery_read_timeout: Duration,
    pub ip_addr_wait: Duration,
    pub exchange_timeout: Duration,
    pub dendrite: bool,
    pub dpd_port: u16,
    pub dpd_host: String,
    pub exchange_tcp_port: u16,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            solicit_interval: SOLICIT_INTERVAL,
            expire_threshold: EXPIRE_THRESHOLD,
            discovery_read_timeout: DISCOVERY_READ_TIMEOUT,
            ip_addr_wait: IP_ADDR_WAIT,
            exchange_timeout: EXCHANGE_TIMEOUT,
            dpd_port: dpd_client::default_port(),
            dpd_host: "localhost".into(),
            exchange_tcp_port: EXCHANGE_TCP_PORT,
            dendrite: true,
        }
    }
}

pub fn handler(
    addr: IpAddr,
    port: u16,
    admin_port_file: Option<Utf8PathBuf>,
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

    // TODO(#740): unify dropshot logger level handling with `mgd`, which
    // runs its dropshot logger at the parent log level.
    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("admin")
    .map_err(|e| e.to_string())?
    .new(o!(
        "component" => crate::COMPONENT_DDM,
        "module" => crate::MOD_ADMIN,
        "unit" => UNIT_API_SERVER,
    ));

    let api = api_description().map_err(|e| e.to_string())?;

    // Bind the port synchronously, so bind failures propagate to the caller and
    // (in case of binding to port 0) the OS-assigned port is known.
    let server = dropshot::ServerBuilder::new(api, context, ds_log)
        .config(config)
        .version_policy(dropshot::VersionPolicy::Dynamic(Box::new(
            dropshot::ClientSpecifiesVersionInHeader::new(
                omicron_common::api::VERSION_HEADER,
                ddm_api::latest_version(),
            ),
        )))
        .start()
        .map_err(|e| format!("admin: server start error: {e:?}"))?;

    let bound = server.local_addr();
    info!(log, "admin: listening on {bound}");

    if let Some(path) = admin_port_file {
        port_file::write(&path, bound).map_err(|e| {
            // Render the full error chain.
            InlineErrorChain::new(&e).to_string()
        })?;
    }

    spawn(async move {
        match server.await {
            Ok(()) => info!(log, "admin: server exited"),
            Err(e) => error!(log, "admin: server error {:?}", e),
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
        let ctx = lock!(ctx.context());
        let mut result = HashMap::new();
        for sm in &ctx.peers {
            // Compute status first so peer_status() never runs while we hold
            // any of the InterfaceState mutexes below.
            let status = sm.iface.peer_status();
            let if_index = *lock!(sm.iface.if_index);
            let Some(peer) = lock!(sm.iface.peer_identity).clone() else {
                continue;
            };
            result.insert(
                if_index,
                PeerInfo {
                    status,
                    addr: peer.addr,
                    host: peer.hostname,
                    kind: peer.kind,
                },
            );
        }
        Ok(HttpResponseOk(result))
    }

    async fn expire_peer(
        ctx: RequestContext<Self::Context>,
        params: Path<ExpirePathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let addr = params.into_inner().addr;
        let ctx = lock!(ctx.context());

        for e in ctx.event_channels() {
            e.send(Event::Admin(AdminEvent::Expire(addr)))
                .map_err(|e| {
                    HttpError::for_internal_error(format!(
                        "admin event send: {e}"
                    ))
                })?;
        }

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

        for e in ctx.event_channels() {
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

        for e in ctx.event_channels() {
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

        for e in ctx.event_channels() {
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

        for e in ctx.event_channels() {
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

    async fn sync(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let ctx = lock!(ctx.context());

        for e in ctx.event_channels() {
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
        let (jh, log) = {
            let ctx = lock!(ctx.context());
            (ctx.stats_handler.clone(), ctx.log.clone())
        };

        let mut jh = lock!(jh);
        if jh.is_none() {
            let hostname = hostname::get()
                .expect("failed to get hostname")
                .to_string_lossy()
                .to_string();
            *jh = Some(
                crate::oxstats::start_server(
                    DDM_STATS_PORT,
                    ctx.context().clone(),
                    hostname,
                    rq.rack_id,
                    rq.sled_id,
                    log,
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

    async fn set_external_peers(
        ctx: RequestContext<Self::Context>,
        request: TypedBody<ExternalPeers>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mut ctx = lock!(ctx.context());

        if ctx.router_kind != RouterKind::Transit {
            return Err(HttpError::for_bad_request(
                None,
                "external peers only supported for transit routers".into(),
            ));
        }

        let rq = request.into_inner();

        let current = ctx.db.get_external_peers();
        let to_create = rq.address_objects.difference(&current);
        let to_remove = current.difference(&rq.address_objects);

        info!(ctx.log, "peer change request";
            "requested" => ?rq.address_objects,
            "to_create" => ?to_create,
            "to_remove" => ?to_remove,
            "current" => ?current,
        );
        ctx.db.set_external_peers(rq.address_objects.clone());

        for addr_obj in to_create.into_iter() {
            let (tx, rx) = channel();

            let config = crate::sm::Config {
                solicit_interval: ctx.tunables.solicit_interval,
                expire_threshold: ctx.tunables.expire_threshold,
                discovery_read_timeout: ctx.tunables.discovery_read_timeout,
                ip_addr_wait: ctx.tunables.ip_addr_wait,
                exchange_timeout: ctx.tunables.exchange_timeout,
                exchange_port: ctx.tunables.exchange_tcp_port,
                aobj_name: addr_obj.clone(),
                if_name: String::default(), // initialized in state machine
                if_index: 0,                // initialized in state machine
                // External peers are only a thing for transit routers.
                kind: RouterKind::Transit,
                dpd: if ctx.tunables.dendrite {
                    Some(crate::sm::DpdConfig {
                        host: ctx.tunables.dpd_host.clone(),
                        port: ctx.tunables.dpd_port,
                    })
                } else {
                    None
                },
                addr: Ipv6Addr::UNSPECIFIED,
                rack_id: ctx.rack_id,
                sled_id: ctx.sled_id,
            };
            let sm_ctx = SmContext {
                config,
                db: ctx.db.clone(),
                event_channels: ctx.event_channels().cloned().collect(),
                tx: tx.clone(),
                log: ctx.log.clone(),
                router_id: ctx.router_id.clone(),
                rt: Arc::new(tokio::runtime::Handle::current()),
                iface: Arc::new(InterfaceState::external()),
                stats: Arc::new(SessionStats::default()),
                discovery_stop: None,
                first_run: true,
            };
            let mut sm = StateMachine {
                ctx: sm_ctx.clone(),
                rx: Some(rx),
            };

            sm.run().unwrap();

            ctx.peers.push(sm_ctx.clone());
        }

        // Ensure our indices are unique and ordered.
        let mut remove_idx = BTreeSet::default();

        for aobj in to_remove.into_iter() {
            for (i, p) in ctx.peers.iter().enumerate() {
                if p.iface.external {
                    if &p.config.aobj_name == aobj {
                        let _ = p.tx.send(Event::Admin(AdminEvent::Shutdown));
                        remove_idx.insert(i);
                        info!(
                            ctx.log,
                            "removing external peeer for address object {aobj}"
                        );
                    } else {
                        debug!(ctx.log, "{aobj} != {}", p.config.aobj_name);
                    }
                }
            }
        }
        // remove peers back to front so we don't shift the order our from under
        // ourselves for the indexes we just gathered.
        for i in remove_idx.iter().rev() {
            ctx.peers.remove(*i);
        }

        Ok(HttpResponseUpdatedNoContent())
    }

    async fn get_external_peers(
        ctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<ExternalPeers>, HttpError> {
        let ctx = lock!(ctx.context());

        if ctx.router_kind != RouterKind::Transit {
            return Err(HttpError::for_bad_request(
                None,
                "external peers only supported for transit routers".into(),
            ));
        }

        Ok(HttpResponseOk(ExternalPeers {
            address_objects: ctx.db.get_external_peers(),
        }))
    }
}

pub fn api_description()
-> Result<ApiDescription<Arc<Mutex<HandlerContext>>>, ApiDescriptionBuildErrors>
{
    ddm_admin_api_mod::api_description::<DdmAdminApiImpl>()
}
