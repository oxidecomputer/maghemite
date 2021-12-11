use std::io::{Result, ErrorKind, Error};
use std::sync::Arc;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;

use tokio::{spawn, select};
use tokio::time::sleep;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tokio::sync::broadcast;
use slog::{self, trace, info, warn, error, Logger};
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
use crate::graph::{Graph, shortest_path};
use crate::{router_info, router_warn, router_error, router_trace};
use crate::flowstat::PortStats;

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
    //pub local_prefix_update: Arc::<Notify>,
    pub linkstate_update: broadcast::Sender<(String, SrpLink)>,
    pub prefix_update: broadcast::Sender<SrpPrefix>,

    linkstate_counter: Arc::<AtomicU64>,
    prefix_counter: Arc::<AtomicU64>,
}


#[derive(Clone)]
pub(crate) struct RouterRuntime<Platform: platform::Full> {
    pub(crate) router: Arc::<Router>,
    pub(crate) platform: Arc::<Mutex::<Platform>>,
    pub(crate) config: Config,
    pub(crate) log: Logger,
}

pub struct RouterState {
    pub peers: HashMap::<String, Arc::<Mutex::<PeerStatus>>>,
    pub local_prefixes: HashSet::<Ipv6Prefix>,
    pub remote_prefixes: HashMap::<String, HashSet::<Ipv6Prefix>>,
    pub graph: Graph<String>,

    // most recent messages
    pub(crate) prefixes: HashSet::<SrpPrefix>,
    pub(crate) links: HashSet::<SrpLink>,

    pub(crate) path_map: HashMap::<String, Vec::<String>>,
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
            path_map: HashMap::new(),
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

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Peer {
    pub port_index: u16,
    pub name: String,
}

impl Router {

    pub fn new(name: String, kind: RouterKind) -> Self {
        let (lstx, _) = broadcast::channel(0x20);
        let (pftx, _) = broadcast::channel(0x20);
        Router{
            info: RouterInfo{name, kind},
            state: Arc::new(Mutex::new(RouterState::new())),
            linkstate_update: lstx,
            prefix_update: pftx,
            linkstate_counter: Arc::new(AtomicU64::new(0)),
            prefix_counter: Arc::new(AtomicU64::new(0)),
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
            let r = RouterRuntime{
                router: r.clone(),
                platform: p,
                config: config,
                log: log.clone()
            };

            // run the I/O thread, this starts with peering and then makes its 
            // way to SRP protocol I/O with linkstate messages and such.
            spawn(async move{

                router_info!(r.log, &r.router.info.name, "running router");
                match Self::run_thread(r.clone()).await {
                    Ok(()) => {},
                    Err(e) => {
                        router_error!(r.log, &r.router.info.name, e, "run");
                    }
                }

            });
        }

        if r.info.kind == RouterKind::Transit {

            // run the path calculator thread
            {
                let log = log.clone();
                let state = r.state.clone();
                let info = r.info.clone();
                spawn(async move {
                    Self::run_path_calculator(log, info, state).await;
                });
            }

            // run the state estimator thread
            {
                let log = log.clone();
                let state = r.state.clone();
                spawn(async move {
                    Self::run_state_estimator(log, state).await;
                });
            }

            // run the prefix delegator thread
            {
                let log = log.clone();
                let state = r.state.clone();
                spawn(async move {
                    Self::run_prefix_distributor(log, state).await;
                });
            }

        }

        Ok(())
    }

    async fn run_thread<Platform>(r: RouterRuntime<Platform>) -> Result<()>
    where
        Platform: platform::Full
    {
        let ports = r.platform.lock().await.ports()?;
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
        let (tx, mut rx) = match r.platform.lock().await.peer_channel(port) {
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

    async fn run_path_calculator(
        log: Logger,
        info: RouterInfo,
        state: Arc::<Mutex::<RouterState>>,
    ) {
        router_info!(log, info.name, "starting path calculator");

        loop {
            // get a sanpshot of our current peers and the net graph
            let (prefixes, graph) = {
                let state = state.lock().await;
                let prefixes = state.prefixes.clone();
                let graph = state.graph.clone();
                (prefixes, graph)
            };

            // we are only interested in paths to server routers

            // local path map
            let mut path_map = HashMap::new();

            // find shortest path from this router to every server router
            // TODO: do this on concurrent threads?
            for p in prefixes {
                let name = p.origin;
                let p = shortest_path(&graph, info.name.clone(), name.clone());
                if p.len() < 2 {
                    router_warn!(log, info.name, "no path to {}", &name);
                }
                path_map.insert(name.clone(), p);
            }

            // update the path map
            {
                let mut state = state.lock().await;
                for (k,v) in path_map {
                    state.path_map.insert(k, v);
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

    }

    async fn run_state_estimator(
        _log: Logger,
        _state: Arc::<Mutex::<RouterState>>,
    ) {
        // TOOD
    }

    async fn run_prefix_distributor(
        _log: Logger,
        _state: Arc::<Mutex::<RouterState>>,
    ) {
        // TOOD
    }

    async fn run_srp_io_sm<Platform>(
        r: RouterRuntime<Platform>,
        port: Port,
        peer: RouterInfo,
        peer_status: Arc::<Mutex::<PeerStatus>>,
    )
    where
        Platform: platform::Full
    {

        // get srp channel
        let (tx, mut rx) = {
                match r.platform.lock().await.srp_channel(port) {
                Ok(pair) =>  pair,
                Err(e) => {
                    router_error!(
                        r.log,
                        r.router.info.name,
                        e,
                        "get srp channel for {:?}",
                        port
                    );
                    panic!("failed to get srp channel");
                }
            }
        };


        // send out periodic link state updates
        {
            let local = r.router.info.clone();
            let log = r.log.clone();
            let state = r.router.state.clone();
            let lsupdate = r.router.linkstate_update.clone();
            let mut counter = 0u64;
            let peername = peer.name.clone();
            let p = r.platform;

            spawn(async move { loop {

                let stats = match p.lock().await.stats(port) {
                    Ok(s) => s,
                    Err(e) => {
                        router_error!(log, local.name, e, "get link stats");
                        PortStats::new()
                    }
                };

                // TODO we should only send out a link update when there is
                // actually some delta from our last, but we need rate info
                // to determine that, so just fire at will for now.
                let link = SrpLink{
                    origin: local.name.clone(),
                    neighbor: peername.clone(),
                    capacity: 0, // TODO
                    egress_rate: stats.egress_rate,
                    ingress_rate: stats.ingresss_rate,
                    // TODO not yet sure what Ordering should be here
                    //serial: linkstate_counter.fetch_add(1, Ordering::Relaxed),
                    serial: counter,
                };
                counter += 1;

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
                                log, local.name, e, "send srp link update: {}");
                        }
                    }
                }
                */
                // broadcast to transit peers
                match lsupdate.send(("".into(), link)) {
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
            let local = r.router.info.clone();
            let tx = tx.clone();
            let log = r.log.clone();
            let state= r.router.state.clone();
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

                        router_trace!(
                            log, local.name, "local prefix update");
                        let mut origin = local.name.clone();

                        let prefixes = 
                            state.lock().await.local_prefixes.clone();

                        // XXX gross hack, get the data flow right
                        if msg.origin.as_str() != "" {
                            origin = msg.origin
                        }

                        let msg = SrpPrefix{
                            origin, 
                            prefixes,
                            serial: 0,
                        };

                        match tx.send(SrpMessage::Prefix(msg)).await {
                            Ok(_) => {},
                            Err(e) => {
                                router_error!(log, local.name, e, "srp prefix tx");
                            }
                        }

                    }

                }


            }});
        }

        // handle lsupdate messages 
        if peer.kind == RouterKind::Transit {
            let mut rx = r.router.linkstate_update.subscribe();
            let tx = tx.clone();
            let log = r.log.clone();
            let local = r.router.info.clone();
            let name = peer.name.clone();

            spawn(async move { loop {

                match rx.recv().await {
                    Ok(msg) => {

                        // do not flood messages back to sender
                        if msg.0 == name {
                            continue
                        }
                        //router_debug!(log, local.name, "T: {}", msg.serial);
                        match tx.send(SrpMessage::Link(msg.1)).await {
                            Ok(_) => { 
                                let mut g = peer_status.lock().await;
                                let x: &mut PeerStatus = &mut *g;
                                //peer_status.lock().await.ls_sent += 1;
                                x.ls_sent += 1;
                                //let x = peer_status.lock().await.ls_sent;
                                if local.name == "tr00" && x.ls_sent % 100 == 0 {
                                    router_warn!(
                                        log, 
                                        local.name,
                                        "Sent: {} {}",
                                        name,
                                        x.ls_sent
                                    );
                                }
                            }
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
            let log = r.log.clone();
            let local = r.router.info.clone();
            let state = r.router.state.clone();
            let pfupdate = r.router.prefix_update.clone();
            let lsupdate = r.router.linkstate_update.clone();

            spawn(async move { loop {
                match rx.recv().await {
                    Some(msg) => {

                        router_trace!(log, local.name, "srp rx: {:?}", msg);

                        match msg {
                            SrpMessage::Prefix(p) => {

                                {
                                    let mut state = state.lock().await;

                                    //TODO do we actually need this, or is just
                                    // .   prefix fine
                                    // update remote prefixes
                                    match state.remote_prefixes.get_mut(&p.origin) {
                                        Some(prefix_set) => {
                                            for x in &p.prefixes {
                                                prefix_set.insert(*x);
                                            }
                                        }
                                        None => {
                                            let mut set = HashSet::new();
                                            for x in &p.prefixes {
                                                set.insert(*x);
                                            }
                                            state.remote_prefixes.insert(
                                                p.origin.clone(), set);
                                        }
                                    }

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
                                // TODO this is causing a storm up link state
                                // updates
                                match lsupdate.send((peer.name.clone(), l)) {
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
                Router::run_srp_io_sm(
                    r.clone(),
                    port,
                    RouterInfo{
                        name: pong.sender.clone(),
                        kind: pong.kind,
                    },
                    new,
                ).await;
            }
        }

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


        // wait for routers to start
        sleep(Duration::from_secs(3)).await;

        let client = hyper::Client::new();

        // advertise a prefix at each server
        for i in 10..18 {
            let mut request = HashSet::new();
            request.insert(Ipv6Prefix::from_str(
                &format!("fd00::1701:{}/64", i)
            )?);
            let body = serde_json::to_string(&request)?;

            let req = hyper::Request::builder()
                .method(hyper::Method::PUT)
                .uri(format!("http://127.0.0.1:47{}/prefix", i))
                .body(hyper::Body::from(body))
                .expect("request builder");

            client.request(req).await?;
        }

        sleep(Duration::from_secs(5)).await;

        // get the network graph from t0
        let uri = "http://127.0.0.1:4718/graph".parse()?;
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let g: Graph::<String> = serde_json::from_slice(&body_bytes)?;
        info!(log, "{:#?}", g);

        let p = shortest_path(&g, "sr02".to_string(), "sr12".to_string());
        info!(log, "{:?}", p);

        // get the path map from t0
        let uri = "http://127.0.0.1:4718/paths".parse()?;
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let g: HashMap::<String, Vec::<String>> = 
            serde_json::from_slice(&body_bytes)?;
        info!(log, "{:#?}", g);

        // get peers from t0
        let uri = "http://127.0.0.1:4718/peers".parse()?;
        let resp = client.get(uri).await?;
        assert_eq!(resp.status(), 200);
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let g: HashMap::<String, PeerStatus> = 
            serde_json::from_slice(&body_bytes)?;
        info!(log, "{:#?}", g);


        Ok(())
    }
}