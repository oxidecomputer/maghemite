use std::io::{Result, ErrorKind, Error};
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::{
    spawn, select,
    time::sleep,
    sync::{Mutex, broadcast, mpsc::Sender},
};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use slog::{self, trace, debug, info, warn, error, Logger};

use crate::admin;
use crate::platform;
use crate::config::Config;
use crate::protocol::{RouterKind, DdmMessage, DdmPrefix, PeerMessage, PeerPing, PeerPong};
use crate::{router_info, router_warn, router_error, router_trace, router_debug};
use crate::port::Port;

#[derive(Clone)]
pub(crate) struct RouterRuntime<Platform: platform::Full> {
    pub(crate) router: Arc::<Router>,
    pub(crate) platform: Arc::<Mutex::<Platform>>,
    pub(crate) config: Config,
    pub(crate) log: Logger,
}

pub struct Router {
    pub info: RouterInfo,
    pub state: Arc::<Mutex::<RouterState>>,
    pub prefix_update: broadcast::Sender<DdmPrefix>,
}

impl Router {

    pub fn new(name: String, kind: RouterKind) -> Self {
        let (pftx, _) = broadcast::channel(0x20);
        Router{
            info: RouterInfo{name, kind},
            state: Arc::new(Mutex::new(RouterState::new())),
            prefix_update: pftx,
        }
    }

    pub fn run<Platform>(
        r: Arc::<Router>,
        p: Arc::<Mutex::<Platform>>,
        config: Config,
        log: Logger,
    )
    -> Result<()>
    where
        Platform: platform::Full
    {

        {
            /*
            let r = RouterRuntime{
                router: r.clone(),
                platform: p,
                config: config,
                log: log.clone()
            };
            */

            // run the I/O thread, this starts with peering and then makes its 
            // way to DDP prefix exchange.
            spawn(async move{

                Self::run_sync(r, p, config, log).await;

                /*
                router_info!(r.log, &r.router.info.name, "running router");
                match Self::run_thread(r.clone()).await {
                    Ok(()) => {},
                    Err(e) => {
                        router_error!(r.log, &r.router.info.name, e, "run");
                    }
                }
                */

            });
        }

        Ok(())

    }

    pub async fn run_sync<Platform>(
        r: Arc::<Router>,
        p: Arc::<Mutex::<Platform>>,
        config: Config,
        log: Logger,
    )
    -> Result<()>
    where
        Platform: platform::Full
    {

        {
            let r = RouterRuntime{
                router: r.clone(),
                platform: p,
                config: config,
                log: log.clone()
            };

            router_info!(r.log, &r.router.info.name, "running router");
            match Self::run_thread(r.clone()).await {
                Ok(()) => {},
                Err(e) => {
                    router_error!(r.log, &r.router.info.name, e, "run");
                }
            }

        }

        Ok(())

    }

    async fn run_thread<Platform>(r: RouterRuntime<Platform>) -> Result<()>
    where
        Platform: platform::Full
    {
        let ports = r.platform.lock().await.ports().await?;
        for port in ports {
            Router::run_peer_sm(r.clone(), port).await;
        }

        admin::handler(r.clone())
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(())

    }

    async fn run_peer_sm<Platform>(r: RouterRuntime<Platform>, port: Port)
    where
        Platform: platform::Full
    {

        // get peer channel
        let (tx, mut rx) = match r.platform.lock().await.peer_channel(port).await {
            Ok(pair) =>  pair,
            Err(e) => {
                router_error!(
                    r.log,
                    r.router.info.name,
                    e,
                    "get peer channel for {:?}",
                    port
                );
                panic!("failed to get peer channel");
            }
        };


        // send out periodic peer pings
        {
            let info = r.router.info.clone();
            let tx = tx.clone();
            let log = r.log.clone();

            spawn(async move { loop {

                let ping = PeerMessage::Ping(
                    PeerPing{sender :info.name.clone()});

                match tx.send(ping).await {
                    Ok(_) => {},
                    Err(e) => {
                        router_error!(log, info.name, e, "send peer msg");
                    }
                }

                sleep(Duration::from_millis(100)).await;

            }});

        }

        // handle peer messages
        {
            let info = r.router.info.clone();
            let tx = tx.clone();
            let log = r.log.clone();

            spawn(async move { loop {
                    router_trace!(log, info.name, "sending ping");
                    router_trace!(log, info.name, "waiting for pong");
                    select! {
                        resp = rx.recv() => {
                            match resp {
                                Some(msg) => {
                                    match msg {
                                        PeerMessage::Ping(ping) => {
                                            handle_ping(
                                                info.clone(),
                                                &ping,
                                                &tx,
                                                &log).await;
                                        }
                                        PeerMessage::Pong(pong) => {
                                            handle_pong(
                                                r.clone(),
                                                port,
                                                pong,
                                            ).await;
                                        }
                                    }
                                }
                                None => {
                                    router_warn!(
                                        log, info.name, "recv pong none?");
                                }
                            }
                        }

                    };

            }});
        }

    }

    async fn run_ddm_io_sm<Platform>(
        r: RouterRuntime<Platform>,
        port: Port,
    )
    where
        Platform: platform::Full
    {

        // get ddm channel
        let (tx, mut rx) = {
                match r.platform.lock().await.ddm_channel(port).await {
                Ok(pair) =>  pair,
                Err(e) => {
                    router_error!(
                        r.log,
                        r.router.info.name,
                        e,
                        "get ddm channel for {:?}",
                        port
                    );
                    panic!("failed to get ddm channel");
                }
            }
        };

        // propagate prefix updates
        {
            let local = r.router.info.clone();
            let tx = tx.clone();
            let log = r.log.clone();
            let mut rx = r.router.prefix_update.subscribe();

            spawn(async move { loop {

                match rx.recv().await {
                    Err(e) => {
                        router_error!(
                            log, 
                            local.name,
                            e,
                            "pfupdate rx",
                        );
                    }
                    Ok(msg) => {

                        router_debug!(
                            log, local.name, "local prefix update {:?}", msg);

                        match tx.send(DdmMessage::Prefix(msg)).await {
                            Ok(_) => {},
                            Err(e) => {
                                router_error!(log, local.name, e, "ddm prefix tx");
                            }
                        }

                    }

                }


            }});
        }

        // handle ddm messages
        {
            let log = r.log.clone();
            let local = r.router.info.clone();
            let state = r.router.state.clone();
            let pfupdate = r.router.prefix_update.clone();

            spawn(async move { loop {
                match rx.recv().await {
                    Some(msg) => {

                        router_trace!(log, local.name, "ddm rx: {:?}", msg);

                        match msg {
                            DdmMessage::Prefix(p) => {

                                let mut state = state.lock().await;

                                router_debug!(
                                    log, local.name, "new prefix: {:?}", p);

                                // update prefixes
                                if !state.prefixes.contains(&p) {
                                    state.prefixes.insert(p.clone());
                                    // push update to other peers
                                    match pfupdate.send(p) {
                                        Ok(_) => {}
                                        Err(e) => {
                                            router_error!(
                                                log, 
                                                local.name, 
                                                e,
                                                "pfupdate send"
                                            )
                                        }
                                    }
                                }

                            }
                        }
                    }
                    None => {
                        router_warn!(log, local.name, "ddm rx none?");
                    }
                }
            }});
        }
    }

}

async fn handle_ping(
    local: RouterInfo,
    ping: &PeerPing,
    tx: &Sender<PeerMessage>,
    log: &Logger
) {
    router_trace!(log, local.name, "ping: {:?}", ping);
    let pong = PeerMessage::Pong(PeerPong{
        sender: local.name.clone(),
        origin: ping.sender.clone(),
        kind: local.kind,
    });
    match tx.send(pong).await {
        Ok(_) => { }
        Err(e) => {
            router_error!(log, local.name, e, "send pong resp");
        }
    }
}

async fn handle_pong<Platform>(
    r: RouterRuntime<Platform>,
    port: Port,
    pong: PeerPong,
) 
where
    Platform: platform::Full
{
    router_trace!(r.log, r.router.info.name, "pong: {:?}", pong);
    let mut state = r.router.state.lock().await;
    let prev = state.peers.get(&pong.sender);
    match prev {
        Some(_) => {}
        None => {
            let new = Arc::new(Mutex::new(PeerStatus::new(pong.kind)));
            state.peers.insert(
                pong.sender.clone(), new.clone(),
            );
            router_info!(
                r.log,
                r.router.info.name,
                "added new peer {}",
                &pong.sender
            );
            Router::run_ddm_io_sm(
                r.clone(),
                port,
            ).await;
        }
    }

}

#[derive(Debug, Clone)]
pub struct RouterInfo {
    pub name: String,
    pub kind: RouterKind,
}

pub struct RouterState {
    pub peers: HashMap::<String, Arc::<Mutex::<PeerStatus>>>,
    pub(crate) prefixes: HashSet::<DdmPrefix>,
}

impl RouterState {
    pub fn new() -> Self {
        RouterState{
            peers: HashMap::new(),
            prefixes: HashSet::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PeerStatus {
    kind: RouterKind,
    ls_sent: u128,
    ls_recvd: u128,
}

impl PeerStatus {
    fn new(kind: RouterKind) -> Self {
        PeerStatus{
            kind,
            ls_sent: 0,
            ls_recvd: 0,
        }
    }
}

pub struct Route {
}

#[cfg(test)]
mod test {
    use crate::mimos;
    use crate::router::PeerStatus;
    use crate::net::Ipv6Prefix;
    use crate::protocol::{DdmPrefix, RouterKind};

    use tokio::time::sleep;

    use std::time::Duration;
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;

    use slog_term;
    use slog_async;
    use slog::{info, Drain};

    fn test_logger() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_envlogger::new(drain).fuse();
        let drain = slog_async::Async::new(drain).chan_size(5000).build().fuse();
        let log = slog::Logger::root(drain, slog::o!());
        log
    }

    #[tokio::test]
    async fn mimos_ddm_2_router_peer() -> anyhow::Result<()> {

        let log = test_logger();

        // topology
        let mut a = mimos::Node::new("a".into(), RouterKind::Server);
        let mut b = mimos::Node::new("b".into(), RouterKind::Server);
        mimos::connect(&mut a, &mut b).await;

        // run routers
        a.run(4705, log.clone())?;
        b.run(4706, log.clone())?;

        // wait for peering to take place
        sleep(Duration::from_secs(1)).await;

        // check peering status
        let client = hyper::Client::new();
        for port in &[4705, 4706] {
            let uri = format!("http://127.0.0.1:{}/peers", port).parse()?;
            let resp = client.get(uri).await?;
            assert_eq!(resp.status(), 200);
            let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
            let peers: HashMap<String, PeerStatus> =
                serde_json::from_slice(&body_bytes)?;
            assert_eq!(1, peers.len());
        }

        Ok(())
    }

    #[tokio::test]
    async fn mimos_ddm_2_router_advertise_prefix() -> anyhow::Result<()> {

        let log = test_logger();

        // topology
        let mut a = mimos::Node::new("a".into(), RouterKind::Server);
        let mut b = mimos::Node::new("b".into(), RouterKind::Server);
        mimos::connect(&mut a, &mut b).await;

        // run routers
        a.run(4707, log.clone())?;
        b.run(4708, log.clone())?;

        // wait for peering to take place
        sleep(Duration::from_secs(1)).await;

        // advertise prefix
        let client = hyper::Client::new();
        let mut request = HashSet::new();
        request.insert(Ipv6Prefix::from_str("fd00::1701/64")?);
        let body = serde_json::to_string(&request)?;

        let req = hyper::Request::builder()
            .method(hyper::Method::PUT)
            .uri("http://127.0.0.1:4707/prefix")
            .body(hyper::Body::from(body))
            .expect("request builder");

        client.request(req).await?;

        // wait for prefix propagation
        sleep(Duration::from_secs(1)).await;

        // look for the advertised prefix in adjacent router
        let uri = "http://127.0.0.1:4708/prefixes".parse()?; 
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let prefixes: HashSet::<DdmPrefix> =
            serde_json::from_slice(&body_bytes)?;
        assert_eq!(1, prefixes.len());

        let host = "a".to_string();
        let mut expected = HashSet::new();
        expected.insert(Ipv6Prefix::from_str("fd00::1701/64")?);
        let mut found = false;
        for x in prefixes {
            if x.origin == host {
                assert_eq!(&x.prefixes, &expected);
                found = true;
                break;
            }
        }
        assert_eq!(found, true);


        Ok(())
    }

    #[tokio::test]
    async fn mimos_ddm_12_router_adv() -> anyhow::Result<()> {

        let log = test_logger();

        // routers

        let mut port = 4720;

        // server routers
        // rack 0
        let mut s0 = Vec::new();
        for i in 0..4 {
            let n = mimos::Node::new(format!("sr0{}", i), RouterKind::Server);
            s0.push(n);
        }
        //rack 1
        let mut s1 = Vec::new();
        for i in 0..4 {
            let n = mimos::Node::new(format!("sr1{}", i), RouterKind::Server);
            s1.push(n);
        }
        // transit routers
        // rack 0
        let mut t0 = Vec::new();
        for i in 0..2 {
            let n = mimos::Node::new(format!("tr0{}", i), RouterKind::Transit);
            t0.push(n);
        }
        // rack 1
        let mut t1 = Vec::new();
        for i in 0..2 {
            let n = mimos::Node::new(format!("tr1{}", i), RouterKind::Transit);
            t1.push(n);
        }

        // connections

        // rack 1
        for mut x in &mut s0 {
            mimos::connect(&mut x, &mut t0[0]).await;
            mimos::connect(&mut x, &mut t0[1]).await;
        }
        // rack 2
        for mut x in &mut s1 {
            mimos::connect(&mut x, &mut t1[0]).await;
            mimos::connect(&mut x, &mut t1[1]).await;
        }
        // cross rack
        for mut x in &mut t0 {
            mimos::connect(&mut x, &mut t1[0]).await;
            mimos::connect(&mut x, &mut t1[1]).await;
        }

        for x in &mut s0 {
            x.run(port, log.clone())?;
            port += 1;
        }
        for x in &mut s1 {
            x.run(port, log.clone())?;
            port += 1;
        }
        for x in &mut t0 {
            x.run(port, log.clone())?;
            port += 1;
        }
        for x in &mut t1 {
            x.run(port, log.clone())?;
            port += 1;
        }


        // wait for routers to start
        sleep(Duration::from_secs(3)).await;

        let client = hyper::Client::new();

        // advertise a prefix at each server
        for i in 20..28 {
            let mut request = HashSet::new();
            request.insert(Ipv6Prefix::from_str(
                &format!("fd00:1701:{}::/64", i)
            )?);
            let body = serde_json::to_string(&request)?;

            let req = hyper::Request::builder()
                .method(hyper::Method::PUT)
                .uri(format!("http://127.0.0.1:47{}/prefix", i))
                .body(hyper::Body::from(body))
                .expect("request builder");

            client.request(req).await?;
        }

        sleep(Duration::from_secs(8)).await;

        // look for the advertised prefixes
        let uri = "http://127.0.0.1:4720/prefixes".parse()?; 
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let prefixes: HashSet::<DdmPrefix> =
            serde_json::from_slice(&body_bytes)?;
        println!("prefixes: {:#?}", prefixes);
        assert_eq!(8, prefixes.len());

        let mut i = 20;
        for host in &["sr00", "sr01", "sr02", "sr03", "sr10", "sr11", "sr12", "sr13"] {
            let host = host.to_string();
            let mut expected = HashSet::new();
            let addr = format!("fd00:1701:{}::/64", i);
            expected.insert(Ipv6Prefix::from_str(addr.as_str())?);
            let mut found = false;
            for x in &prefixes {
                if x.origin == host {
                    assert_eq!(&x.prefixes, &expected);
                    found = true;
                    break;
                }
            }
            assert_eq!(found, true);
            i+=1;
        }

        Ok(())
    }
}
