use dropshot::{
    endpoint,
    ConfigDropshot,
    ApiDescription,
    HttpServerStarter,
    RequestContext,
    HttpResponseOk,
    HttpError,
    TypedBody,
};

use tokio::sync::{Mutex, broadcast};
use std::sync::Arc;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::collections::{HashSet, HashMap};

use slog::info;

use crate::router_info;
use crate::config::Config;
use crate::router::{RouterState, PeerStatus, RouterRuntime, RouterInfo};
use crate::net::Ipv6Prefix;
use crate::protocol::DdmPrefix;
use crate::platform;

pub struct ArcAdmContext {
    pub config: Config,
    pub info: RouterInfo,
    pub state: Arc::<Mutex::<RouterState>>,
    pub pfupdate: broadcast::Sender<DdmPrefix>,
}

#[endpoint { method = GET, path = "/ping" }]
async fn adm_ping(
    _ctx: Arc<RequestContext<ArcAdmContext>>,
) -> Result<HttpResponseOk<String>, HttpError> {

    Ok(HttpResponseOk("pong".to_string()))

}

#[endpoint { method = GET, path = "/peers" }]
async fn get_peers(
    ctx: Arc<RequestContext<ArcAdmContext>>,
) -> Result<HttpResponseOk<HashMap::<String, PeerStatus>>, HttpError> {

    let api_context = ctx.context();

    let peers = api_context.state.lock().await.peers.clone();
    let mut result = HashMap::new();

    for (k,v) in peers {
        result.insert(k, *v.lock().await); 
    }

    Ok(HttpResponseOk(result))

}

#[endpoint { method = GET, path = "/prefixes" }]
async fn get_prefixes(
    ctx: Arc<RequestContext<ArcAdmContext>>,
) -> Result<HttpResponseOk<HashSet::<DdmPrefix>>, HttpError> {

    let api_context = ctx.context();

    Ok(HttpResponseOk(api_context.state.lock().await.prefixes.clone()))

}

#[endpoint { method = PUT, path = "/prefix" }]
async fn advertise_prefix(
    ctx: Arc<RequestContext<ArcAdmContext>>,
    body_param: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let api_context = ctx.context();
    let body: HashSet<Ipv6Prefix> = body_param.into_inner();

    let prefixes = &mut api_context.state.lock().await.prefixes;
    let x = DdmPrefix{
        origin: api_context.info.name.clone(),
        prefixes: body.clone(),
        serial: 0,
    };
    prefixes.insert(x.clone());
    api_context.pfupdate.send(
        x.clone()
    ).map_err(|e| HttpError::for_internal_error(format!("{}", e)))?;


    Ok(HttpResponseOk(()))

}


pub(crate) async fn handler<Platform: platform::Full>(
    r: RouterRuntime<Platform>
) -> Result<(), String> {

    let addr = SocketAddr::V4(
        SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), r.config.admin_port)
    );

    let config_dropshot = ConfigDropshot{
        bind_address: addr,
        ..Default::default()
    };

    let mut api = ApiDescription::new();
    api.register(adm_ping)?;
    api.register(get_peers)?;
    api.register(advertise_prefix)?;
    api.register(get_prefixes)?;

    let api_context = ArcAdmContext{
        config: r.config,
        info: r.router.info.clone(),
        state: r.router.state.clone(),
        pfupdate: r.router.prefix_update.clone(),
    };

    let server = HttpServerStarter::new(
        &config_dropshot,
        api,
        api_context,
        &r.log,
    ).map_err(|e| format!("create dropshot adm server: {}", e))?
    .start();

    router_info!(r.log, r.router.info.name, "starting adm server");

    server.await

}

#[cfg(test)]
mod test {
    use crate::mimos;
    use crate::protocol::RouterKind;

    use tokio::time::sleep;
    use std::time::Duration;

    use slog_term;
    use slog_async;
    use slog::Drain;

    #[tokio::test]
    async fn mimos_adm_ping() -> anyhow::Result<()> {

        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_envlogger::new(drain).fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let log = slog::Logger::root(drain, slog::o!());

        let a = mimos::Node::new("a".into(), RouterKind::Server);
        a.run(4710, log)?;

        sleep(Duration::from_secs(1)).await;

        let client = hyper::Client::new();

        let uri = "http://127.0.0.1:4710/ping".parse()?;
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);

        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body, "\"pong\"");


        Ok(())

    }


}
