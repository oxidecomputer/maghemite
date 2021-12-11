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

use crate::{router_info};
use crate::config::Config;
use crate::router::{RouterState, PeerStatus, RouterRuntime};
use crate::net::Ipv6Prefix;
use crate::graph::Graph;
use crate::protocol::SrpPrefix;
use crate::platform;

pub struct ArcAdmContext {
    pub config: Config,
    pub state: Arc::<Mutex::<RouterState>>,
    pub pfupdate: broadcast::Sender<SrpPrefix>,
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

    Ok(HttpResponseOk(api_context.state.lock().await.peers.clone()))

}

#[endpoint { method = GET, path = "/remote_prefixes" }]
async fn get_remote_prefixes(
    ctx: Arc<RequestContext<ArcAdmContext>>,
) -> Result<HttpResponseOk<
        HashMap::<String, HashSet::<Ipv6Prefix>>>, 
        HttpError
    > {

    let api_context = ctx.context();

    Ok(HttpResponseOk(api_context.state.lock().await.remote_prefixes.clone()))

}

#[endpoint { method = GET, path = "/graph" }]
async fn get_graph(
    ctx: Arc<RequestContext<ArcAdmContext>>,
) -> Result<HttpResponseOk<Graph::<String>>, HttpError> {

    let api_context = ctx.context();

    Ok(HttpResponseOk(api_context.state.lock().await.graph.clone()))
    
}

#[endpoint { method = GET, path = "/paths" }]
async fn get_paths(
    ctx: Arc<RequestContext<ArcAdmContext>>,
) -> Result<HttpResponseOk<HashMap::<String, Vec::<String>>>, HttpError> {

    let api_context = ctx.context();

    Ok(HttpResponseOk(api_context.state.lock().await.path_map.clone()))
    
}

#[endpoint { method = PUT, path = "/prefix" }]
async fn advertise_prefix(
    ctx: Arc<RequestContext<ArcAdmContext>>,
    body_param: TypedBody<HashSet<Ipv6Prefix>>,
) -> Result<HttpResponseOk<()>, HttpError> {

    let api_context = ctx.context();
    let body: HashSet<Ipv6Prefix> = body_param.into_inner();

    let local_prefixes = &mut api_context.state.lock().await.local_prefixes;
    for x in &body {
        local_prefixes.insert(*x);
    }

    //TODO: like lsupdate
    //api_context.local_prefix_notifier.notify_one();
    api_context.pfupdate.send(
        SrpPrefix{
            origin: "".into(),
            prefixes: body.clone(),
            serial: 0,
        }
    ).map_err(|e| HttpError::for_internal_error(format!("{}", e)))?;

    Ok(HttpResponseOk(()))

}


pub(crate) async fn handler<Platform: platform::Full>(
    r: RouterRuntime<Platform>
) -> Result<(), String> {

    let addr = SocketAddr::V4(
        SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), r.config.port)
    );

    let config_dropshot = ConfigDropshot{
        bind_address: addr,
        ..Default::default()
    };

    let mut api = ApiDescription::new();
    api.register(adm_ping)?;
    api.register(get_peers)?;
    api.register(advertise_prefix)?;
    api.register(get_remote_prefixes)?;
    api.register(get_graph)?;
    api.register(get_paths)?;

    let api_context = ArcAdmContext{
        config: r.config,
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