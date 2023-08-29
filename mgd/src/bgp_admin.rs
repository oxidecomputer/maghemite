use crate::admin::HandlerContext;
use bgp::config::{PeerConfig, RouterConfig};
use bgp::connection::BgpConnectionTcp;
use bgp::connection::BgpListenerTcp;
use bgp::fanout::Rule4;
use bgp::router::Router;
use bgp::session::Asn;
use bgp::session::FsmEvent;
use dropshot::{
    endpoint, HttpError, HttpResponseOk, HttpResponseUpdatedNoContent,
    RequestContext, TypedBody,
};
use rdb::{Policy, PolicyAction, Prefix4, Route4ImportKey, Route4Key};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::info;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread::spawn;

pub struct BgpContext {
    router: Mutex<Option<Arc<Router<BgpConnectionTcp>>>>,
}

impl Default for BgpContext {
    fn default() -> Self {
        Self {
            router: Mutex::new(None),
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

//TODO use bgp::config::PeerConfig instead
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddNeighborRequest {
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddExportPolicyRequest {
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
    /// Nexthop to originate.
    pub nexthop: Ipv4Addr,

    /// Set of prefixes to originate.
    pub prefixes: Vec<Prefix4>,
}

#[endpoint { method = POST, path = "/bgp/router" }]
pub async fn new_router(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<NewRouterRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let mut guard = ctx.context().bgp.router.lock().unwrap();
    if guard.is_some() {
        return Err(HttpError::for_bad_request(
            None,
            "bgp router already configured".into(),
        ));
    }

    let rq = request.into_inner();

    let cfg = RouterConfig {
        asn: Asn::FourOctet(rq.asn),
        id: rq.id,
    };

    //assumes only one router per machine
    let db = rdb::Db::new("/var/run/rdb").unwrap();

    let router = Arc::new(Router::<BgpConnectionTcp>::new(
        rq.listen,
        cfg,
        ctx.context().log.clone(),
        db.clone(),
    ));

    let rtr = router.clone();
    spawn(move || {
        rtr.run::<BgpListenerTcp>();
    });

    let rt = Arc::new(tokio::runtime::Handle::current());
    let log = ctx.log.clone();
    spawn(move || {
        mg_lower::run(db, log, rt);
    });

    *guard = Some(router);

    Ok(HttpResponseUpdatedNoContent())
}

macro_rules! get_router {
    ($ctx:expr) => {
        $ctx.context().bgp.router.lock().unwrap().as_deref().ok_or(
            HttpError::for_not_found(None, "no bgp router configured".into()),
        )?
    };
}

#[endpoint { method = POST, path = "/bgp/neighbor" }]
pub async fn add_neighbor(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddNeighborRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let log = ctx.context().log.clone();
    let rq = request.into_inner();

    info!(log, "add neighbor: {:#?}", rq);

    let (event_tx, event_rx) = channel();

    get_router!(&ctx).new_session(
        PeerConfig {
            name: rq.name.clone(),
            host: rq.host,
            hold_time: rq.hold_time,
            idle_hold_time: rq.idle_hold_time,
            delay_open: rq.delay_open,
            connect_retry: rq.connect_retry,
            keepalive: rq.keepalive,
            resolution: rq.resolution,
        },
        "0.0.0.0:179".parse().unwrap(),
        event_tx.clone(),
        event_rx,
    );
    event_tx.send(FsmEvent::ManualStart).unwrap();

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/export-policy" }]
pub async fn add_export_policy(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddExportPolicyRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();

    get_router!(&ctx).add_export_policy(
        rq.addr,
        Rule4 {
            prefix: rq.prefix,
            policy: Policy {
                action: rq.action,
                priority: rq.priority,
            },
        },
    );

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = POST, path = "/bgp/originate4" }]
pub async fn originate4(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<Originate4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = request.into_inner();
    let prefixes = rq.prefixes.into_iter().map(Into::into).collect();

    get_router!(&ctx)
        .originate4(rq.nexthop, prefixes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = GET, path = "/bgp/originate4" }]
pub async fn get_originated4(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<Route4Key>>, HttpError> {
    let originated = get_router!(&ctx)
        .db
        .get_originated4()
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/bgp/imported4" }]
pub async fn get_imported4(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<Route4ImportKey>>, HttpError> {
    let imported = get_router!(&ctx).db.get_imported4();
    Ok(HttpResponseOk(imported))
}
