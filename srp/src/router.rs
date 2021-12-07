use std::io::{Result, ErrorKind, Error};
use std::sync::Arc;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::{spawn, select};
use tokio::time::sleep;
use tokio::sync::{Mutex, Notify};
use tokio::sync::mpsc::Sender;
use tokio::sync::broadcast;
use slog::{self, debug, trace, info, warn, error, Logger};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

use crate::admin;
use crate::platform;
use crate::port::Port;
use crate::config::Config;
use crate::protocol::{
    RouterKind,
    PeerMessage, PeerPing, PeerPong, 
    SrpLink, SrpMessage, SrpPrefix,
};
use crate::net::Ipv6Prefix;
use crate::graph::Graph;
use crate::{router_info, router_warn, router_debug, router_error, router_trace};

pub struct Route {
}

#[derive(Debug, Clone)]
pub struct RouterInfo {
    pub name: String,
    pub kind: RouterKind,
}

pub struct Router {
    pub info: RouterInfo,
    pub state: Arc::<Mutex::<RouterState>>,
    pub local_prefix_update: Arc::<Notify>,
    pub linkstate_update: broadcast::Sender<SrpLink>,

    linkstate_counter: Arc::<AtomicU64>,
    prefix_counter: Arc::<AtomicU64>,
}

pub struct RouterState {
    pub peers: HashMap::<String, PeerStatus>,
    pub local_prefixes: HashSet::<Ipv6Prefix>,
    pub remote_prefixes: HashMap::<String, HashSet::<Ipv6Prefix>>,
    pub graph: Graph<String>,

    // most recent messages
    prefixes: HashSet::<SrpPrefix>,
    links: HashSet::<SrpLink>,
}

impl RouterState {
    pub fn new() -> Self {
        RouterState{
            peers: HashMap::new(),
            local_prefixes: HashSet::new(),
            remote_prefixes: HashMap::new(),
            graph: Graph::new(),
            prefixes: HashSet::new(),
            links: HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PeerStatus {
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Peer {
    pub port_index: u16,
    pub name: String,
}

impl Router {

    pub fn new(name: String, kind: RouterKind) -> Self {
        // TODO This channel should not need to be anywhere near this big ....
        // .    some major contention going on somehwere
        let (tx, _) = broadcast::channel(0x2000);
        Router{
            info: RouterInfo{name, kind},
            state: Arc::new(Mutex::new(RouterState::new())),
            local_prefix_update: Arc::new(Notify::new()),
            linkstate_update: tx,
            linkstate_counter: Arc::new(AtomicU64::new(0)),
            prefix_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn run<Platform>(
        &self,
        p: Arc::<Mutex::<Platform>>,
        config: Config,
        log: Logger,
    )
    -> Result<()>
    where
        Platform: platform::Full + Send + Sync + 'static
    {

        let state = self.state.clone();
        let local_prefix_notifier = self.local_prefix_update.clone();
        let info = self.info.clone();
        let lsupdate = self.linkstate_update.clone();
        let linkstate_counter = self.linkstate_counter.clone();

        spawn(async move{
            router_info!(log, &info.name, "running router");
            match Self::run_thread(
                info.clone(),
                p,
                state,
                local_prefix_notifier,
                lsupdate,
                config,
                log.clone(),
                linkstate_counter,
            ).await {
                Ok(()) => {},
                Err(e) => {
                    router_error!(log, &info.name, e, "run");
                }
            }
        });

        Ok(())
    }

    async fn run_thread<Platform>(
        info: RouterInfo,
        p: Arc::<Mutex::<Platform>>,
        state: Arc::<Mutex::<RouterState>>,
        local_prefix_notifier: Arc::<Notify>,
        lsupdate: broadcast::Sender<SrpLink>,
        config: Config,
        log: Logger,
        linkstate_counter: Arc::<AtomicU64>,
    )
    -> Result<()>
    where
        Platform: platform::Full + Send + 'static
    {
        let ports = p.lock().await.ports()?;

        for port in ports {
            Router::run_peer_sm(
                info.clone(),
                p.clone(),
                state.clone(),
                local_prefix_notifier.clone(),
                lsupdate.clone(),
                port,
                log.clone(),
                linkstate_counter.clone(),
            ).await;
        }

        admin::handler(
            info,
            config, state.clone(),
            local_prefix_notifier.clone(),
            log.clone()).await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        Ok(())

    }

    async fn run_peer_sm<Platform>(
        info: RouterInfo,
        p: Arc::<Mutex::<Platform>>,
        state: Arc::<Mutex::<RouterState>>,
        local_prefix_notifier: Arc::<Notify>,
        lsupdate: broadcast::Sender<SrpLink>,
        port: Port,
        log: Logger,
        linkstate_counter: Arc::<AtomicU64>,
    )
    where
        Platform: platform::Full + Send + 'static
    {

        // get peer channel
        let (tx, mut rx) = match p.lock().await.peer_channel(port) {
            Ok(pair) =>  pair,
            Err(e) => {
                router_error!(
                    log, info.name, e, "get peer channel for {:?}", port);
                panic!("failed to get peer channel");
            }
        };


        // send out periodic peer pings
        {
            let info = info.clone();
            let tx = tx.clone();
            let log = log.clone();

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
            let info = info.clone();
            let tx = tx.clone();
            let log = log.clone();

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
                                                info.clone(),
                                                &pong,
                                                &log,
                                                &state,
                                                local_prefix_notifier.clone(),
                                                lsupdate.clone(),
                                                &p,
                                                port,
                                                linkstate_counter.clone(),
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

    async fn run_arc_sm<Platform>(
        local: RouterInfo,
        peer: RouterInfo,
        p: Arc::<Mutex::<Platform>>,
        state: Arc::<Mutex::<RouterState>>,
        local_prefix_notifier: Arc::<Notify>,
        lsupdate: broadcast::Sender<SrpLink>,
        port: Port,
        log: Logger,
        linkstate_counter: Arc::<AtomicU64>,
    )
    where
        Platform: platform::Full + Send + 'static
    {

        // get arc channel
        let (tx, mut rx) = match p.lock().await.arc_channel(port) {
            Ok(pair) =>  pair,
            Err(e) => {
                router_error!(
                    log, local.name, e, "get arc channel for {:?}", port);
                panic!("failed to get arc channel");
            }
        };


        // send out periodic link state updates
        {
            let local = local.clone();
            let tx = tx.clone();
            let log = log.clone();
            let state = state.clone();
            let lsupdate = lsupdate.clone();
            spawn(async move { loop {

                // TODO we should only send out a link update when there is
                // actually some delta from our last, but we need rate info
                // to determine that, so just fire at will for now.
                let link = SrpLink{
                    origin: local.name.clone(),
                    neighbor: peer.name.clone(),
                    capacity: 0, // TODO
                    egress_rate: 0, // TODO
                    ingress_rate: 0, // TODO
                    // TODO not yet sure what Ordering should be here
                    serial: linkstate_counter.fetch_add(1, Ordering::Relaxed),
                };

                // first update our own state
                // locked region
                if local.kind == RouterKind::Transit {
                    let mut locked_state = state.lock().await;
                    locked_state.links.insert(link.clone());
                    locked_state.graph.one_way_insert(
                        link.origin.clone(),
                        link.neighbor.clone(),
                        link.ingress_rate,
                    );
                }


                /*

                TODO this only works if transit routers relay link state
                     messages. Which is something we should probably consider
                     anyhow. In fact it may be necessary in some cases. A
                     single Oxide rack is a bipartite graph with one set being
                     the servers and the other being the sidecars. In this case
                     it's clear that without link-state message relay by the
                     server-level routers, the rack level routers will never
                     observe each others link state.

                let link_update = SrpMessage::Link(link.clone()); 
                if peer.kind == RouterKind::Transit {
                    match tx.send(link_update).await {
                        Ok(_) => {},
                        Err(e) => {
                            router_error!(
                                log, local.name, e, "send arc link update: {}");
                        }
                    }
                }
                */
                // broadcast to transit peers
                match lsupdate.send(link) {
                    Ok(_) => {}
                    Err(e) => {
                        router_error!(
                            log, 
                            local.name, 
                            e,
                            "lsupdate send"
                        )
                    }
                }


                sleep(Duration::from_millis(100)).await;

            }});
        }

        // propagate local prefix updates
        {
            let local = local.clone();
            let tx = tx.clone();
            let log = log.clone();
            let state= state.clone();

            spawn(async move { loop {

                local_prefix_notifier.notified().await;

                router_debug!(
                    log, local.name, "local prefix update notification");
                let origin = local.name.clone();

                let prefixes = 
                    state.lock().await.local_prefixes.clone();

                let msg = SrpPrefix{
                    origin, 
                    prefixes,
                    serial: 0,
                };

                match tx.send(SrpMessage::Prefix(msg)).await {
                    Ok(_) => {},
                    Err(e) => {
                        router_error!(log, local.name, e, "arc prefix tx");
                    }
                }

            }});
        }

        // handle lsupdate messages 
        if peer.kind == RouterKind::Transit {
            let mut rx = lsupdate.subscribe();
            let tx = tx.clone();
            let log = log.clone();
            let local = local.clone();

            spawn(async move { loop {

                match rx.recv().await {
                    Ok(msg) => {
                        match tx.send(SrpMessage::Link(msg)).await {
                            Ok(_) => {}
                            Err(e) => {
                                router_error!(
                                    log,
                                    local.name,
                                    e,
                                    "flood link tx"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        router_error!(
                            log,
                            local.name,
                            e,
                            "flood link rx"
                        );
                    }
                }

            }});
        }

        // handle srp messages
        {
            let log = log.clone();

            spawn(async move { loop {
                match rx.recv().await {
                    Some(msg) => {

                        router_trace!(log, local.name, "srp rx: {:?}", msg);

                        match msg {
                            SrpMessage::Prefix(p) => {
                                let prefixes = &mut state
                                    .lock()
                                    .await
                                    .remote_prefixes;

                                match prefixes.get_mut(&p.origin) {
                                    Some(prefix_set) => {
                                        for x in p.prefixes {
                                            prefix_set.insert(x);
                                        }
                                    }
                                    None => {
                                        let mut set = HashSet::new();
                                        for x in p.prefixes {
                                            set.insert(x);
                                        }
                                        prefixes.insert(p.origin, set);
                                    }
                                }
                            }

                            SrpMessage::Link(l) => {
                                router_trace!(
                                    log, local.name, "srp link rx: {:?}", l);

                                if local.kind != RouterKind::Transit {
                                    router_warn!(
                                        log,
                                        local.name,
                                        "unexpected link state update: {:?}",
                                        l
                                    );
                                    continue;
                                }

                                // locked state region
                                {
                                    let mut locked_state = state.lock().await;

                                    // ignore updates that are older than what
                                    // we currently have
                                    match locked_state.links.get(&l) {
                                        Some(current) => {
                                            if current.serial >= l.serial {
                                                    continue
                                            }
                                        }
                                        None => { }
                                    }

                                    // update the most recent link update from
                                    // this peer
                                    locked_state.links.insert(l.clone());

                                    // update the link state graph
                                    locked_state.graph.one_way_insert(
                                        l.origin.clone(),
                                        l.neighbor.clone(),
                                        l.ingress_rate
                                    );
                                }

                                // push the update to our other peers
                                match lsupdate.send(l) {
                                    Ok(_) => {}
                                    Err(e) => {
                                        router_error!(
                                            log, 
                                            local.name, 
                                            e,
                                            "lsupdate send"
                                        )
                                    }
                                }

                                // Signal retransmit for other peers
                                // we need something like a vector clock
                                // here to ensure consistency ....
                                // or rather, we are at the part of the lsdb
                                // algorithm where we need to enforce some
                                // sort of flooding/consistency model
                            }

                            SrpMessage::SyncRequest(_) => {
                                //TODO
                            }

                            SrpMessage::SyncResponse(_) => {
                                //TODO
                            }
                        }
                    }
                    None => {
                        router_warn!(log, local.name, "srp rx none?");
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
    info: RouterInfo,
    pong: &PeerPong,
    log: &Logger,
    state: &Arc::<Mutex::<RouterState>>,
    local_prefix_notifier: Arc::<Notify>,
    lsupdate: broadcast::Sender<SrpLink>,
    p: &Arc::<Mutex::<Platform>>,
    port: Port,
    linkstate_counter: Arc::<AtomicU64>,
) 
where
    Platform: platform::Full + Send + 'static
{
    router_trace!(log, info.name, "pong: {:?}", pong);
    let prev = state.lock().await.peers.insert(
        pong.sender.clone(), PeerStatus{}
    );
    if prev.is_none() {
        router_info!(log, info.name, "added new peer {}", &pong.sender);
    }
    Router::run_arc_sm(
        info,
        RouterInfo{
            name: pong.sender.clone(),
            kind: pong.kind,
        },
        p.clone(),
        state.clone(),
        local_prefix_notifier,
        lsupdate,
        port,
        log.clone(),
        linkstate_counter,
    ).await;
}

#[cfg(test)]
mod test {
    use crate::mimos;
    use crate::router::PeerStatus;
    use crate::net::Ipv6Prefix;
    use crate::protocol::RouterKind;
    use crate::graph::{Graph, shortest_path};

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
    async fn mimos_2_router_peer() -> anyhow::Result<()> {

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
    async fn mimos_2_router_advertise_prefix() -> anyhow::Result<()> {

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
        let uri = "http://127.0.0.1:4708/remote_prefixes".parse()?; 
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let prefixes: HashMap<String, HashSet::<Ipv6Prefix>> =
            serde_json::from_slice(&body_bytes)?;
        assert_eq!(1, prefixes.len());

        let host = "a".to_string();
        let mut expected = HashSet::new();
        expected.insert(Ipv6Prefix::from_str("fd00::1701/64")?);
        assert_eq!(prefixes.get(&host), Some(&expected));


        Ok(())
    }

    #[tokio::test]
    async fn mimos_12_router_paths() -> anyhow::Result<()> {

        let log = test_logger();

        // routers

        let mut port = 4710;

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

        sleep(Duration::from_secs(5)).await;

        // get the network graph from t0
        let client = hyper::Client::new();
        let uri = "http://127.0.0.1:4718/graph".parse()?;
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let g: Graph::<String> = serde_json::from_slice(&body_bytes)?;
        info!(log, "{:#?}", g);

        let p = shortest_path(&g, "sr02".to_string(), "sr12".to_string());
        info!(log, "{:?}", p);


        Ok(())
    }
}