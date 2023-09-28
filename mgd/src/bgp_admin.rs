use crate::admin::HandlerContext;
use bgp::config::{PeerConfig, RouterConfig};
use bgp::connection::BgpConnectionTcp;
use bgp::router::Router;
use bgp::session::{Asn, FsmEvent, FsmStateKind};
use dropshot::{
    endpoint, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use http::status::StatusCode;
use rdb::{BgpRouterInfo, PolicyAction, Prefix4, Route4ImportKey, Route4Key};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

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

//TODO use bgp::config::PeerConfig instead
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

    /// Prefix this policy applies to
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

    /// Nexthop to originate.
    pub nexthop: Ipv4Addr,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetImported4Request {
    /// ASN of the router to get imported prefixes from
    pub asn: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetOriginated4Request {
    /// ASN of the router to get originated prefixes from
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
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerInfo {
    pub state: FsmStateKind,
    pub asn: Option<u32>,
    pub duration_millis: u64,
}

#[endpoint { method = GET, path = "/bgp/routers" }]
pub async fn get_routers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<RouterInfo>>, HttpError> {
    let rs = ctx.context().bgp.router.lock().unwrap();
    let mut result = Vec::new();

    for r in rs.values() {
        let mut peers = BTreeMap::new();
        for s in r.sessions.lock().unwrap().values() {
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
    ensure_router(ctx.clone(), rq).await
}

pub async fn ensure_router(
    ctx: Arc<HandlerContext>,
    rq: NewRouterRequest,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let mut guard = ctx.bgp.router.lock().unwrap();
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

    let mut guard = ctx.bgp.router.lock().unwrap();
    if guard.get(&rq.asn).is_some() {
        return Err(HttpError::for_status(
            Some("bgp router with specified ASN exists".into()),
            StatusCode::CONFLICT,
        ));
    }

    add_router(ctx.clone(), rq, &mut guard)
}

pub(crate) fn add_router(
    ctx: Arc<HandlerContext>,
    rq: NewRouterRequest,
    routers: &mut BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
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
    )
    .unwrap();

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/bgp/router" }]
pub async fn delete_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let mut routers = ctx.context().bgp.router.lock().unwrap();
    if let Some(r) = routers.remove(&rq.asn) {
        r.shutdown()
    };

    Ok(HttpResponseUpdatedNoContent())
}

macro_rules! get_router {
    ($ctx:expr, $asn:expr) => {
        $ctx.bgp.router.lock().unwrap().get(&$asn).ok_or(
            HttpError::for_not_found(None, "no bgp router configured".into()),
        )
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
    add_neighbor(ctx.clone(), rq, log).await
}

pub async fn add_neighbor(
    ctx: Arc<HandlerContext>,
    rq: AddNeighborRequest,
    log: Logger,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    info!(log, "add neighbor: {:#?}", rq);

    let (event_tx, event_rx) = channel();

    match get_router!(&ctx, rq.asn)?.new_session(
        rq.clone().into(),
        "0.0.0.0:179".parse().unwrap(),
        event_tx.clone(),
        event_rx,
    ) {
        Ok(_) => {}
        Err(bgp::error::Error::PeerExists) => {
            return Err(HttpError::for_status(
                Some("bgp peer with specified address exists".into()),
                StatusCode::CONFLICT,
            ));
        }
        Err(e) => {
            return Err(HttpError::for_internal_error(format!("{:?}", e)))
        }
    }
    event_tx.send(FsmEvent::ManualStart).unwrap();

    ctx.db
        .add_bgp_neighbor(rdb::BgpNeighborInfo {
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
        })
        .unwrap(); //TODO unwrap

    Ok(HttpResponseUpdatedNoContent())
}

pub async fn remove_neighbor(
    ctx: Arc<HandlerContext>,
    asn: u32,
    addr: IpAddr,
    log: Logger,
) -> Result<HttpResponseDeleted, HttpError> {
    info!(log, "remove neighbor: {}", addr);

    ctx.db.remove_bgp_neighbor(addr).unwrap(); //TODO unwrap
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
    let log = ctx.log.clone();
    remove_neighbor(ctx.clone(), rq.asn, rq.addr, log).await
}

#[endpoint { method = PUT, path = "/bgp/neighbor" }]
pub async fn ensure_neighbor_handler(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();
    let ctx = ctx.context();
    ensure_neighbor(ctx.clone(), rq, log)
}

pub fn ensure_neighbor(
    ctx: Arc<HandlerContext>,
    rq: AddNeighborRequest,
    log: Logger,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    info!(log, "add neighbor: {:#?}", rq);

    let (event_tx, event_rx) = channel();

    match get_router!(&ctx, rq.asn)?.new_session(
        rq.into(),
        "0.0.0.0:179".parse().unwrap(),
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
    event_tx.send(FsmEvent::ManualStart).unwrap();

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
        .originate4(rq.nexthop, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/originate4" }]
pub async fn get_originated4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<GetOriginated4Request>,
) -> Result<HttpResponseOk<Vec<Route4Key>>, HttpError> {
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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ApplyRequest {
    pub asn: u32,
    pub peer_group: String,
    pub peers: Vec<BgpPeerConfig>,
    pub routes: Vec<BgpRoute>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct BgpRoute {
    pub nexthop: Ipv4Addr,
    pub prefixes: Vec<Prefix4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct BgpPeerConfig {
    // Session properties
    pub host: SocketAddr,
    pub name: String,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
}

#[endpoint { method = POST, path = "/bgp/apply" }]
pub async fn bgp_apply(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<ApplyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();

    info!(log, "apply: {rq:#?}");

    if !rq.peers.is_empty() {
        ensure_router(
            ctx.context().clone(),
            NewRouterRequest {
                asn: rq.asn,
                id: rq.asn,
                listen: "[::]:179".to_string(), //TODO hardcode
            },
        )
        .await?;
    }

    let current: Vec<rdb::BgpNeighborInfo> = ctx
        .context()
        .db
        .get_bgp_neighbors()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?
        .into_iter()
        .filter(|x| x.group == rq.peer_group)
        .collect();

    let current_nbr_addrs: HashSet<IpAddr> =
        current.iter().map(|x| x.host.ip()).collect();

    let specified_nbr_addrs: HashSet<IpAddr> =
        rq.peers.iter().map(|x| x.host.ip()).collect();

    let to_delete = current_nbr_addrs.difference(&specified_nbr_addrs);
    let to_add = specified_nbr_addrs.difference(&current_nbr_addrs);

    info!(log, "adding {to_add:#?}");
    info!(log, "removing {to_delete:#?}");

    for nbr in to_add {
        let cfg = rq.peers.iter().find(|x| x.host.ip() == *nbr).unwrap();
        add_neighbor(
            ctx.context().clone(),
            AddNeighborRequest::from_bgp_peer_config(
                rq.asn,
                rq.peer_group.clone(),
                cfg.clone(),
            ),
            log.clone(),
        )
        .await?;
    }

    for nbr in to_delete {
        remove_neighbor(ctx.context().clone(), rq.asn, *nbr, log.clone())
            .await?;
    }

    if rq.peers.is_empty() {
        let mut routers = ctx.context().bgp.router.lock().unwrap();
        let mut remove = false;
        if let Some(r) = routers.get(&rq.asn) {
            remove = r.sessions.lock().unwrap().is_empty();
        }
        if remove {
            if let Some(r) = routers.remove(&rq.asn) {
                r.shutdown()
            };
        }
    }

    for x in rq.routes {
        let prefixes = x.prefixes.into_iter().map(Into::into).collect();
        get_router!(ctx.context(), rq.asn)?
            .originate4(x.nexthop, prefixes)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    }

    Ok(HttpResponseUpdatedNoContent())
}
