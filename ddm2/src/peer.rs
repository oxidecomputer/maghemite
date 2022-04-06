// DDM Peering

// TODO(you are here)
//
// - Plumb in dropshot server
// - Generate clients
// - Implement 3-way peering handshake
// - Implement keepalives

use std::net::{SocketAddrV6, Ipv6Addr};
use std::time::{Instant, Duration};
use std::sync::Arc;

use tokio::{spawn, time::{sleep, timeout}, sync::Mutex, task::JoinHandle};
use slog::{Logger, warn, error};
use hyper::body::HttpBody;
use dropshot::{
    endpoint,
    ConfigDropshot,
    ConfigLogging,
    ConfigLoggingLevel,
    ApiDescription,
    HttpServerStarter,
    RequestContext,
    HttpResponseOk,
    HttpError,
    HttpServer,
    TypedBody,
};

use crate::protocol::{Ping, Pong, RouterKind};

#[derive(Clone)]
pub struct Session {
    log: Logger,
    ifnum: i32,
    addr: Ipv6Addr,
    interval: u64,
    expire: u64,
    state: Arc::<Mutex::<State>>,
    client_task: Option<Arc::<JoinHandle<()>>>,
    server_task: Option<Arc::<JoinHandle<()>>>,

    host: String,
    server_addr: Ipv6Addr,
    server_port: u16,
}

pub struct State {
    last_seen: Option<Instant>,
}

impl State {
    fn new() -> Self {
        State{ last_seen: None }
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Status {
    NoContact,
    Active,
    Expired,
}

impl Session {
    pub fn new(
        log: Logger,
        ifnum: i32,
        addr: Ipv6Addr,
        interval: u64,
        expire: u64,
        host: String,
        server_addr: Ipv6Addr,
        server_port: u16,
    ) -> Self {
        Session{
            log,
            ifnum,
            addr,
            interval,
            expire,
            state: Arc::new(Mutex::new(State::new())),
            client_task: None,
            server_task: None,
            host,
            server_addr,
            server_port,
        }
    }

    pub async fn start(&mut self) -> Result<(), String> {

        //
        // start ping server
        //
        
        self.server_task = Some(Arc::new(self.start_server()?));

        //
        // start ping client
        //
        
        self.client_task = Some(Arc::new(self.run()));

        Ok(())
    }


    pub async fn status(&self) -> Status {
        match self.state.lock().await.last_seen {
            Some(instant) => {
                if instant.elapsed().as_millis() > self.expire.into() {
                    Status::Expired
                } else {
                    Status::Active
                }
            }
            None => Status::NoContact,
        }
    }

    fn run(&self) -> JoinHandle<()> {
        let session = self.clone();
        spawn(async move { 
            loop {
                let pong = match Self::ping(&session).await {
                    Ok(pong) => pong,
                    Err(e) => {
                        warn!(session.log, "ping: {}", e);
                        sleep(Duration::from_millis(session.interval)).await;
                        continue;
                    }
                };
                if pong.origin != session.host {
                    warn!(session.log, "unexpected pong: {:#?}", pong);
                    sleep(Duration::from_millis(session.interval)).await;
                    continue;
                } 
                session.state.lock().await.last_seen = Some(Instant::now());
                sleep(Duration::from_millis(session.interval)).await;
            }
        })
    }

    async fn ping(s: &Session) -> Result<Pong, String> {

        // XXX we need to use a custom hyper client here, and not a dropshot
        // generated client because hyper is the only rust client that supports
        // scoped ipv6 addresses. Dropshot uses reqwest internally which does
        // not support scoped ipv6 addresses.

        let msg = Ping{sender: s.host.clone()};

        let json = serde_json::to_string(&msg)
            .map_err(|e| e.to_string())?;

        let uri = format!("http://[{}%{}]:{}/ping",
            s.addr,
            s.ifnum,
            s.server_port,
        );

        let client = hyper::Client::new();
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&uri)
            .body(hyper::Body::from(json))
            .map_err(|e| e.to_string())?;

        let resp = client.request(req);

        let mut response = match timeout(Duration::from_millis(250), resp).await {
            Ok(resp) => match resp {
                Ok(pong) => pong,
                Err(e) => return Err(format!(
                    "hyper send request to {}: {}",
                    &uri,
                    e,
                )),
            },
            Err(_) => return Err(format!("peer request timeout to {}", uri)),
        };

        let body = match response.body_mut().data().await {
            Some(body) => body.map_err(|e| e.to_string())?,
            None => return Err("no body found".to_string()),
        };

        let pong: Pong = serde_json::from_slice(body.as_ref())
            .map_err(|e| e.to_string())?;

        Ok(pong)
    }

    fn start_server(&self) -> Result<JoinHandle<()>, String> {

        let sa = SocketAddrV6::new(self.server_addr, self.server_port, 0, 0);
        let config = ConfigDropshot {
            bind_address: sa.into(),
            ..Default::default()
        };
        let log =
            ConfigLogging::StderrTerminal{level: ConfigLoggingLevel::Error}
            .to_logger("peer")
            .map_err(|e| e.to_string())?;

        let mut api = ApiDescription::new();
        api.register(ping).unwrap();

        let context = HandlerContext{host: self.host.clone(), state: self.state.clone()};

        let server = HttpServerStarter::new(
            &config,
            api,
            context,
            &log,
        ).map_err(|e| format!("new peer dropshot: {}", e))?;

        Ok(spawn(async move {
            match server.start().await {
                Ok(_) => warn!(log, "peer: unexpected server exit"),
                Err(e) => error!(log, "peer: server start error {:?}", e),
            }
        }))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        match self.client_task {
            Some(ref t) => t.abort(),
            None => {},
        }
        match self.server_task {
            Some(ref t) => t.abort(),
            None => {},
        }
    }
}

// Dropshot endpoints =========================================================

struct HandlerContext {
    host: String,
    state: Arc::<Mutex::<State>>,
}

#[endpoint {
    method = POST,
    path = "/ping"
}]
async fn ping(
    ctx: Arc::<RequestContext::<HandlerContext>>,
    rq: TypedBody<Ping>,
) -> Result<HttpResponseOk<Pong>, HttpError> {

    let context = ctx.context();

    Ok(HttpResponseOk(Pong{
        sender: context.host.clone(),
        origin: rq.into_inner().sender,
        kind: RouterKind::Transit,
    }))
}

// Testing ====================================================================

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Result;
    use util::test::testlab_x2;
    use tokio::time::sleep;

    use super::*;

    #[tokio::test]
    async fn peer_session1() -> Result<()> {
        
        let log = util::test::logger();

        //
        // set up testlab interfaces
        //

        let interfaces = testlab_x2("peer1")?;
        let if0 = &interfaces[0];
        let if1 = &interfaces[1];
        let if0_v6 = if0.v6addr().expect("if0 v6 addr");
        let if1_v6 = if1.v6addr().expect("if1 v6 addr");

        //
        // set up peer sessions
        //
        
        let mut s1 = Session::new(
            log.clone(),
            if0.addr.info.index,
            if1_v6,
            50,
            3000,
            "s1".into(),
            if0_v6,
            0x1dd0,
        );

        let mut s2 = Session::new(
            log.clone(),
            if1.addr.info.index,
            if0_v6,
            50,
            3000,
            "s1".into(),
            if1_v6,
            0x1dd0,
        );

        assert_eq!(s1.status().await, Status::NoContact);
        assert_eq!(s2.status().await, Status::NoContact);

        //
        // run peer sessions
        //

        s1.start().await.expect("s1 start");
        s2.start().await.expect("s2 start");

        //
        // wait for peering
        //
        
        sleep(Duration::from_secs(1)).await;

        assert_eq!(s1.status().await, Status::Active);
        assert_eq!(s2.status().await, Status::Active);

        //
        // drop a peer and test expiration
        //

        drop(s2);
        sleep(Duration::from_millis(5000)).await;
        assert_eq!(s1.status().await, Status::Expired);

        Ok(())
    }
}
