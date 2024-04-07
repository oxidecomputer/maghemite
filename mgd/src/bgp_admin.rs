// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::error::Error;
use bgp::{
    config::{PeerConfig, RouterConfig},
    connection::BgpConnection,
    connection_tcp::BgpConnectionTcp,
    messages::Prefix,
    router::Router,
    session::{FsmEvent, FsmStateKind, MessageHistory, SessionInfo},
    BGP_PORT,
};
use dropshot::{
    endpoint, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use http::status::StatusCode;
use rdb::{Asn, BgpRouterInfo, PolicyAction, Prefix4, Route4ImportKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

const DEFAULT_BGP_LISTEN: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BGP_PORT, 0, 0));

#[derive(Clone)]
pub struct BgpContext {
    pub(crate) router: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    addr_to_session:
        Arc<Mutex<BTreeMap<IpAddr, Sender<FsmEvent<BgpConnectionTcp>>>>>,
}

impl BgpContext {
    pub fn new(
        addr_to_session: Arc<
            Mutex<BTreeMap<IpAddr, Sender<FsmEvent<BgpConnectionTcp>>>>,
        >,
    ) -> Self {
        Self {
            router: Arc::new(Mutex::new(BTreeMap::new())),
            addr_to_session,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct NewRouterRequest {
    /// Autonomous system number for this router
    pub asn: u32,

    /// Id for this router
    pub id: u32,

    /// Listening address <addr>:<port>
    pub listen: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteRouterRequest {
    /// Autonomous system number for the router to remove
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct AddNeighborRequest {
    pub asn: u32,

    pub name: String,
    pub host: SocketAddr,
    pub remote_asn: Option<u32>,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
    pub passive: bool,
}

impl From<AddNeighborRequest> for PeerConfig {
    fn from(rq: AddNeighborRequest) -> Self {
        Self {
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
        }
    }
}

impl AddNeighborRequest {
    fn from_bgp_peer_config(
        asn: u32,
        group: String,
        rq: BgpPeerConfig,
    ) -> Self {
        Self {
            asn,
            remote_asn: rq.remote_asn,
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
            passive: rq.passive,
            group: group.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteNeighborRequest {
    pub asn: u32,
    pub addr: IpAddr,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddExportPolicyRequest {
    /// ASN of the router to apply the export policy to.
    pub asn: u32,

    /// Address of the peer to apply this policy to.
    pub addr: IpAddr,

    /// Prefix this policy applies to.
    pub prefix: Prefix4,

    /// Priority of the policy, higher value is higher priority.
    pub priority: u16,

    /// The policy action to apply.
    pub action: PolicyAction,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Originate4Request {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Withdraw4Request {
    /// ASN of the router to originate from.
    pub asn: u32,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetImported4Request {
    /// ASN of the router to get imported prefixes from.
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GracefulShutdownRequest {
    /// ASN of the router to gracefully shut down.
    pub asn: u32,
    /// Set whether or not graceful shutdown is initiated from this router.
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetOriginated4Request {
    /// ASN of the router to get originated prefixes from.
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetRoutersRequest {}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetRouersResponse {
    router: Vec<RouterInfo>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RouterInfo {
    pub asn: u32,
    pub peers: BTreeMap<IpAddr, PeerInfo>,
    pub graceful_shutdown: bool,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerInfo {
    pub state: FsmStateKind,
    pub asn: Option<u32>,
    pub duration_millis: u64,
}

macro_rules! lock {
    ($mtx:expr) => {
        $mtx.lock().expect("lock mutex")
    };
}

#[endpoint { method = GET, path = "/bgp/routers" }]
pub async fn get_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<RouterInfo>>, HttpError> {
    let rs = lock!(ctx.context().bgp.router);
    let mut result = Vec::new();

    for r in rs.values() {
        let mut peers = BTreeMap::new();
        for s in lock!(r.sessions).values() {
            let dur = s.current_state_duration().as_millis() % u64::MAX as u128;
            peers.insert(
                s.neighbor.host.ip(),
                PeerInfo {
                    state: s.state(),
                    asn: s.remote_asn(),
                    duration_millis: dur as u64,
                },
            );
        }
        result.push(RouterInfo {
            asn: match r.config.asn {
                Asn::TwoOctet(asn) => asn.into(),
                Asn::FourOctet(asn) => asn,
            },
            peers,
            graceful_shutdown: r.in_graceful_shutdown(),
        });
    }

    Ok(HttpResponseOk(result))
}

#[endpoint { method = PUT, path = "/bgp/router" }]
pub async fn ensure_router_handler(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NewRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();
    Ok(ensure_router(ctx.clone(), rq).await?)
}

async fn ensure_router(
    ctx: Arc<HandlerContext>,
    rq: NewRouterRequest,
) -> Result<HttpResponseUpdatedNoContent, Error> {
    let mut guard = lock!(ctx.bgp.router);
    if guard.get(&rq.asn).is_some() {
        return Ok(HttpResponseUpdatedNoContent());
    }

    add_router(ctx.clone(), rq, &mut guard)
}

#[endpoint { method = POST, path = "/bgp/router" }]
pub async fn new_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NewRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    let mut guard = lock!(ctx.bgp.router);
    if guard.get(&rq.asn).is_some() {
        return Err(HttpError::for_status(
            Some("bgp router with specified ASN exists".into()),
            StatusCode::CONFLICT,
        ));
    }

    Ok(add_router(ctx.clone(), rq, &mut guard)?)
}

pub(crate) fn add_router(
    ctx: Arc<HandlerContext>,
    rq: NewRouterRequest,
    routers: &mut BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>,
) -> Result<HttpResponseUpdatedNoContent, Error> {
    let cfg = RouterConfig {
        asn: Asn::FourOctet(rq.asn),
        id: rq.id,
    };

    let db = ctx.db.clone();

    let router = Arc::new(Router::<BgpConnectionTcp>::new(
        cfg,
        ctx.log.clone(),
        db.clone(),
        ctx.bgp.addr_to_session.clone(),
    ));

    router.run();

    routers.insert(rq.asn, router);
    db.add_bgp_router(
        rq.asn,
        BgpRouterInfo {
            id: rq.id,
            listen: rq.listen.clone(),
        },
    )?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/bgp/router" }]
pub async fn delete_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let mut routers = lock!(ctx.context().bgp.router);
    if let Some(r) = routers.remove(&rq.asn) {
        r.shutdown()
    };

    Ok(HttpResponseUpdatedNoContent())
}

macro_rules! get_router {
    ($ctx:expr, $asn:expr) => {
        lock!($ctx.bgp.router)
            .get(&$asn)
            .ok_or(Error::NotFound("no bgp router configured".into()))
    };
}

#[endpoint { method = POST, path = "/bgp/neighbor" }]
pub async fn add_neighbor_handler(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();
    let ctx = ctx.context();
    add_neighbor(ctx.clone(), rq, log).await?;
    Ok(HttpResponseUpdatedNoContent())
}

async fn add_neighbor(
    ctx: Arc<HandlerContext>,
    rq: AddNeighborRequest,
    log: Logger,
) -> Result<(), Error> {
    info!(log, "add neighbor: {:#?}", rq);

    let (event_tx, event_rx) = channel();

    let info = SessionInfo {
        passive_tcp_establishment: rq.passive,
        remote_asn: rq.remote_asn,
        ..Default::default()
    };

    get_router!(&ctx, rq.asn)?.new_session(
        rq.clone().into(),
        DEFAULT_BGP_LISTEN,
        event_tx.clone(),
        event_rx,
        info,
    )?;

    ctx.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
        asn: rq.asn,
        remote_asn: rq.remote_asn,
        name: rq.name.clone(),
        host: rq.host,
        hold_time: rq.hold_time,
        idle_hold_time: rq.idle_hold_time,
        delay_open: rq.delay_open,
        connect_retry: rq.connect_retry,
        keepalive: rq.keepalive,
        resolution: rq.resolution,
        group: rq.group.clone(),
        passive: rq.passive,
    })?;

    start_bgp_session(&event_tx)?;

    Ok(())
}

async fn remove_neighbor(
    ctx: Arc<HandlerContext>,
    asn: u32,
    addr: IpAddr,
) -> Result<HttpResponseDeleted, Error> {
    info!(ctx.log, "remove neighbor: {}", addr);

    ctx.db.remove_bgp_neighbor(addr)?;
    get_router!(&ctx, asn)?.delete_session(addr);

    Ok(HttpResponseDeleted())
}

#[endpoint { method = DELETE, path = "/bgp/neighbor" }]
pub async fn delete_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteNeighborRequest>,
) -> Result<HttpResponseDeleted, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    Ok(remove_neighbor(ctx.clone(), rq.asn, rq.addr).await?)
}

#[endpoint { method = PUT, path = "/bgp/neighbor" }]
pub async fn ensure_neighbor_handler(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    ensure_neighbor(ctx.clone(), rq)
}

pub(crate) fn ensure_neighbor(
    ctx: Arc<HandlerContext>,
    rq: AddNeighborRequest,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    info!(ctx.log, "add neighbor: {:#?}", rq);

    let (event_tx, event_rx) = channel();

    let info = SessionInfo {
        passive_tcp_establishment: rq.passive,
        ..Default::default()
    };

    match get_router!(&ctx, rq.asn)?.new_session(
        rq.into(),
        DEFAULT_BGP_LISTEN,
        event_tx.clone(),
        event_rx,
        info,
    ) {
        Ok(_) => {}
        Err(bgp::error::Error::PeerExists) => {
            return Ok(HttpResponseUpdatedNoContent());
        }
        Err(e) => {
            return Err(HttpError::for_internal_error(format!("{:?}", e)));
        }
    }
    start_bgp_session(&event_tx)?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/originate4" }]
pub async fn originate4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Originate4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .originate4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/withdraw4" }]
pub async fn withdraw4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Withdraw4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();
    let ctx = ctx.context();

    get_router!(ctx, rq.asn)?
        .withdraw4(prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/originate4" }]
pub async fn get_originated4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<GetOriginated4Request>,
) -> Result<HttpResponseOk<Vec<Prefix4>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let originated = get_router!(ctx, rq.asn)?
        .db
        .get_originated4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/bgp/imported4" }]
pub async fn get_imported4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<GetImported4Request>,
) -> Result<HttpResponseOk<Vec<Route4ImportKey>>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    let imported = get_router!(ctx, rq.asn)?.db.get_imported4();
    Ok(HttpResponseOk(imported))
}

#[endpoint { method = POST, path = "/bgp/graceful_shutdown" }]
pub async fn graceful_shutdown(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<GracefulShutdownRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();
    get_router!(ctx, rq.asn)?
        .graceful_shutdown(rq.enabled)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

/// Apply changes to an ASN.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ApplyRequest {
    /// ASN to apply changes to.
    pub asn: u32,
    /// Complete set of prefixes to originate. Any active prefixes not in this
    /// list will be removed. All prefixes in this list are ensured to be in
    /// the originating set.
    pub originate: Vec<Prefix4>,
    /// Lists of peers indexed by peer group. Set's within a peer group key are
    /// a total set. For example, the value
    ///
    /// ```text
    /// {"foo": [a, b, d]}
    /// ```
    /// Means that the peer group "foo" only contains the peers `a`, `b` and
    /// `d`. If there is a peer `c` currently in the peer group "foo", it will
    /// be removed.
    pub peers: HashMap<String, Vec<BgpPeerConfig>>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct BgpPeerConfig {
    pub host: SocketAddr,
    pub remote_asn: Option<u32>,
    pub name: String,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub passive: bool,
}

#[endpoint { method = POST, path = "/bgp/apply" }]
pub async fn bgp_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();

    info!(log, "apply: {rq:#?}");

    #[derive(Debug, Eq)]
    struct Nbr {
        addr: IpAddr,
        asn: u32,
    }

    impl Hash for Nbr {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.addr.hash(state);
        }
    }

    impl PartialEq for Nbr {
        fn eq(&self, other: &Nbr) -> bool {
            self.addr.eq(&other.addr)
        }
    }

    for (group, peers) in &rq.peers {
        let current: Vec<rdb::BgpNeighborInfo> = ctx
            .context()
            .db
            .get_bgp_neighbors()
            .map_err(Error::Db)?
            .into_iter()
            .filter(|x| &x.group == group)
            .collect();

        let current_nbr_addrs: HashSet<Nbr> = current
            .iter()
            .map(|x| Nbr {
                addr: x.host.ip(),
                asn: x.asn,
            })
            .collect();

        let specified_nbr_addrs: HashSet<Nbr> = peers
            .iter()
            .map(|x| Nbr {
                addr: x.host.ip(),
                asn: rq.asn,
            })
            .collect();

        let to_delete = current_nbr_addrs.difference(&specified_nbr_addrs);
        let to_add = specified_nbr_addrs.difference(&current_nbr_addrs);

        info!(log, "nbr: current {current:#?}");
        info!(log, "nbr: adding {to_add:#?}");
        info!(log, "nbr: removing {to_delete:#?}");

        let mut nbr_config = Vec::new();
        for nbr in to_add {
            let cfg = peers
                .iter()
                .find(|x| x.host.ip() == nbr.addr)
                .ok_or(Error::NotFound(nbr.addr.to_string()))?;
            nbr_config.push((nbr, cfg));
        }

        // TODO all the db modification that happens below needs to happen in a
        // transaction.

        ensure_router(
            ctx.context().clone(),
            NewRouterRequest {
                asn: rq.asn,
                id: rq.asn,
                listen: DEFAULT_BGP_LISTEN.to_string(), //TODO as parameter
            },
        )
        .await?;

        for (nbr, cfg) in nbr_config {
            add_neighbor(
                ctx.context().clone(),
                AddNeighborRequest::from_bgp_peer_config(
                    nbr.asn,
                    group.clone(),
                    cfg.clone(),
                ),
                log.clone(),
            )
            .await?;
        }

        for nbr in to_delete {
            remove_neighbor(ctx.context().clone(), nbr.asn, nbr.addr).await?;

            let mut routers = lock!(ctx.context().bgp.router);
            let mut remove = false;
            if let Some(r) = routers.get(&nbr.asn) {
                remove = lock!(r.sessions).is_empty();
            }
            if remove {
                if let Some(r) = routers.remove(&nbr.asn) {
                    r.shutdown()
                };
            }
        }
    }

    let current_originate: HashSet<Prefix4> = ctx
        .context()
        .db
        .get_originated4()
        .map_err(Error::Db)?
        .into_iter()
        .collect();

    let specified_originate: HashSet<Prefix4> =
        rq.originate.iter().cloned().collect();

    let to_delete = current_originate
        .difference(&specified_originate)
        .map(|x| (*x).into())
        .collect();

    let to_add: Vec<Prefix> = specified_originate
        .difference(&current_originate)
        .map(|x| (*x).into())
        .collect();

    info!(log, "origin: current {current_originate:#?}");
    info!(log, "origin: adding {to_add:#?}");
    info!(log, "origin: removing {to_delete:#?}");

    get_router!(ctx.context(), rq.asn)?
        .originate4(to_add)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    get_router!(ctx.context(), rq.asn)?
        .withdraw4(to_delete)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

fn start_bgp_session<Cnx: BgpConnection>(
    event_tx: &Sender<FsmEvent<Cnx>>,
) -> Result<(), Error> {
    event_tx.send(FsmEvent::ManualStart).map_err(|e| {
        Error::InternalCommunication(
            format!("failed to start bgp session {e}",),
        )
    })
}

#[derive(Debug, Deserialize, JsonSchema, Clone)]
pub struct MessageHistoryRequest {
    asn: u32,
}

#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    by_peer: HashMap<IpAddr, MessageHistory>,
}

#[endpoint { method = GET, path = "/bgp/message-history" }]
pub async fn message_history(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MessageHistoryRequest>,
) -> Result<HttpResponseOk<MessageHistoryResponse>, HttpError> {
    let rq = request.into_inner();
    let ctx = ctx.context();

    let mut result = HashMap::new();

    for (addr, session) in
        get_router!(ctx, rq.asn)?.sessions.lock().unwrap().iter()
    {
        result.insert(*addr, session.message_history.lock().unwrap().clone());
    }

    Ok(HttpResponseOk(MessageHistoryResponse { by_peer: result }))
}
