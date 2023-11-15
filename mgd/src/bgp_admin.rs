use crate::admin::HandlerContext;
use crate::error::Error;
use bgp::{
    config::{PeerConfig, RouterConfig},
    connection::BgpConnection,
    connection_tcp::BgpConnectionTcp,
    router::Router,
    session::{FsmEvent, FsmStateKind},
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
use std::collections::{BTreeMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

const DEFAULT_BGP_LISTEN: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BGP_PORT, 0, 0));

pub struct BgpContext {
    pub(crate) router: Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>,
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
            router: Mutex::new(BTreeMap::new()),
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
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub group: String,
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
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
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

    #[cfg(feature = "default")]
    {
        let rt = Arc::new(tokio::runtime::Handle::current());
        let log = ctx.log.clone();
        let db = db.clone();
        std::thread::spawn(move || {
            mg_lower::run(db, log, rt);
        });
    }

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

    get_router!(&ctx, rq.asn)?.new_session(
        rq.clone().into(),
        DEFAULT_BGP_LISTEN,
        event_tx.clone(),
        event_rx,
    )?;

    ctx.db.add_bgp_neighbor(rdb::BgpNeighborInfo {
        asn: rq.asn,
        name: rq.name.clone(),
        host: rq.host,
        hold_time: rq.hold_time,
        idle_hold_time: rq.idle_hold_time,
        delay_open: rq.delay_open,
        connect_retry: rq.connect_retry,
        keepalive: rq.keepalive,
        resolution: rq.resolution,
        group: rq.group.clone(),
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

    match get_router!(&ctx, rq.asn)?.new_session(
        rq.into(),
        DEFAULT_BGP_LISTEN,
        event_tx.clone(),
        event_rx,
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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ApplyRequest {
    pub peer_group: String,
    pub peers: Vec<BgpPeerConfig>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct BgpPeerConfig {
    pub asn: u32,
    pub host: SocketAddr,
    pub name: String,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
    pub originate: Vec<Prefix4>,
}

#[endpoint { method = POST, path = "/bgp/apply" }]
pub async fn bgp_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();

    info!(log, "apply: {rq:#?}");

    let mut asns: Vec<u32> = rq.peers.iter().map(|x| x.asn).collect();
    asns.sort();
    asns.dedup();

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

    let current: Vec<rdb::BgpNeighborInfo> = ctx
        .context()
        .db
        .get_bgp_neighbors()
        .map_err(Error::Db)?
        .into_iter()
        .filter(|x| x.group == rq.peer_group)
        .collect();

    let current_nbr_addrs: HashSet<Nbr> = current
        .iter()
        .map(|x| Nbr {
            addr: x.host.ip(),
            asn: x.asn,
        })
        .collect();

    let specified_nbr_addrs: HashSet<Nbr> = rq
        .peers
        .iter()
        .map(|x| Nbr {
            addr: x.host.ip(),
            asn: x.asn,
        })
        .collect();

    let to_delete = current_nbr_addrs.difference(&specified_nbr_addrs);
    let to_add = specified_nbr_addrs.difference(&current_nbr_addrs);

    info!(log, "adding {to_add:#?}");
    info!(log, "removing {to_delete:#?}");

    let mut nbr_config = Vec::new();
    for nbr in to_add {
        let cfg = rq
            .peers
            .iter()
            .find(|x| x.host.ip() == nbr.addr)
            .ok_or(Error::NotFound(nbr.addr.to_string()))?;
        nbr_config.push((nbr, cfg));
    }

    // TODO all the db modification that happens below needs to happen in a
    // transaction.

    for asn in asns {
        ensure_router(
            ctx.context().clone(),
            NewRouterRequest {
                asn,
                id: asn,
                listen: DEFAULT_BGP_LISTEN.to_string(), //TODO as parameter
            },
        )
        .await?;
    }

    for (nbr, cfg) in nbr_config {
        add_neighbor(
            ctx.context().clone(),
            AddNeighborRequest::from_bgp_peer_config(
                nbr.asn,
                rq.peer_group.clone(),
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

    for peer in rq.peers {
        let prefixes = peer.originate.into_iter().map(Into::into).collect();
        get_router!(ctx.context(), peer.asn)?
            .originate4(prefixes)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    }

    Ok(HttpResponseUpdatedNoContent())
}

fn start_bgp_session<Cnx: BgpConnection>(
    event_tx: &Sender<FsmEvent<Cnx>>,
) -> Result<(), Error> {
    event_tx.send(FsmEvent::ManualStart).map_err(|e| {
        Error::InternalCommunicationError(format!(
            "failed to start bgp session {e}",
        ))
    })
}
