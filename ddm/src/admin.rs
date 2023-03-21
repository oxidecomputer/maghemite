use crate::db::{Db, Ipv6Prefix, PeerInfo};
use crate::sm::{AdminEvent, Event};
use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::HttpServerStarter;
use dropshot::RequestContext;
use dropshot::TypedBody;
use slog::{error, info, warn, Logger};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::spawn;

#[derive(Clone)]
pub struct HandlerContext {
    event_channels: Vec<Sender<Event>>,
    db: Db,
}

pub fn handler(
    addr: IpAddr,
    port: u16,
    event_channels: Vec<Sender<Event>>,
    db: Db,
    log: Logger,
) -> Result<(), String> {
    let context = Arc::new(Mutex::new(HandlerContext { event_channels, db }));

    let sa: SocketAddr = match addr {
        IpAddr::V4(a) => SocketAddrV4::new(a, port).into(),
        IpAddr::V6(a) => SocketAddrV6::new(a, port, 0, 0).into(),
    };

    let config = ConfigDropshot {
        bind_address: sa,
        ..Default::default()
    };

    let ds_log = ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Error,
    }
    .to_logger("admin")
    .map_err(|e| e.to_string())?;

    let api = api_description()?;

    info!(log, "admin: listening on {}", sa);

    let log = log.clone();
    spawn(async move {
        let server = HttpServerStarter::new(&config, api, context, &ds_log)
            .map_err(|e| format!("new admin dropshot: {}", e))
            .unwrap();

        match server.start().await {
            Ok(_) => warn!(log, "admin: unexpected server exit"),
            Err(e) => error!(log, "admin: server start error {:?}", e),
        }
    });

    Ok(())
}

#[endpoint { method = GET, path = "/peers" }]
async fn get_peers(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashMap<u32, PeerInfo>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    Ok(HttpResponseOk(ctx.db.peers()))
}

type PrefixMap = BTreeMap<Ipv6Addr, HashSet<Ipv6Prefix>>;

#[endpoint { method = GET, path = "/originated" }]
async fn get_originated(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<HashSet<Ipv6Prefix>>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let originated = ctx.db.originated();
    Ok(HttpResponseOk(originated))
}

#[endpoint { method = GET, path = "/prefixes" }]
async fn get_prefixes(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseOk<PrefixMap>, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let imported = ctx.db.imported();

    let mut result = PrefixMap::default();

    for route in imported {
        if let Some(entry) = result.get_mut(&route.nexthop) {
            entry.insert(route.destination);
        } else {
            let mut s = HashSet::new();
            s.insert(route.destination);
            result.insert(route.nexthop, s);
        }
    }

    Ok(HttpResponseOk(result))
}

#[endpoint { method = PUT, path = "/prefix" }]
async fn advertise_prefixes(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let prefixes = request.into_inner();
    ctx.db.originate(&prefixes);

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Announce(prefixes.clone())))
            .unwrap(); //TODO(unwrap)
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/prefix" }]
async fn withdraw_prefixes(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
    request: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();
    let prefixes = request.into_inner();
    ctx.db.withdraw(&prefixes);

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Withdraw(prefixes.clone())))
            .unwrap(); //TODO(unwrap)
    }

    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = PUT, path = "/sync" }]
async fn sync(
    ctx: RequestContext<Arc<Mutex<HandlerContext>>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context().lock().unwrap();

    for e in &ctx.event_channels {
        e.send(Event::Admin(AdminEvent::Sync)).unwrap(); //TODO(unwrap)
    }

    Ok(HttpResponseUpdatedNoContent())
}

pub fn api_description(
) -> Result<ApiDescription<Arc<Mutex<HandlerContext>>>, String> {
    let mut api = ApiDescription::new();
    api.register(get_peers)?;
    api.register(advertise_prefixes)?;
    api.register(withdraw_prefixes)?;
    api.register(get_prefixes)?;
    api.register(get_originated)?;
    api.register(sync)?;
    Ok(api)
}
