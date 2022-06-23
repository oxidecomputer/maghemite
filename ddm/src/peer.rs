//! This file contains peering functionality for DDM. When a DDM router receives
//! a router solicitation on the link-local router discovery address ff02::dd,
//! it will attempt to peer with the solicitor. Peering is initiated by the
//! router sending out a [`protocol::Hail`] message that contains the name of
//! the router and what kind of router it is. If the solicitor sends a hail
//! [`protocol::Response`] that specifies the hailing router as the origin then
//! the hailing router will now consider the soliciting router a peer.
//!
//!              *-----*                        *-----*
//!              |  A  |                        |  B  |
//!              *-----*                        *-----*
//!                 |           solicit            |
//!                 |----------------------------->|
//!                 |        hail(B, server)       |
//!                 |<-----------------------------|
//!                 |     response(A, B, server)   |
//!                 |----------------------------->| * A is an active peer
//!                 |             ...              |
//!                 |                              |
//!                 |        hail(B, server)       |
//!                 |<-----------------------------|
//!                 |     response(A, B, server)   |
//!                 |----------------------------->| * Update A last seen at
//!                 |             ...              |   time <t>.
//!                 |                              |
//!                 |     [periodic hails ...]     |
//!                 |                              |
//!
//! Peering is directional. Router A peering with router B, does not imply B
//! peering with A.
//!
//! Active peers have an expiration time. Periodic hails are required to keep a
//! peer active. Both the expiration time and the hail interval are
//! configuration parameters of a DDM router.

use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::ConfigDropshot;
use dropshot::ConfigLogging;
use dropshot::ConfigLoggingLevel;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpServerStarter;
use dropshot::RequestContext;
use dropshot::TypedBody;
use hyper::body::HttpBody;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use slog::error;
use slog::info;
use slog::trace;
use slog::warn;
use slog::Logger;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio::time::timeout;

use crate::protocol::Hail;
use crate::protocol::Response;
use crate::protocol::RouterKind;

pub struct Session {
    log: Logger,
    client_task: Option<Arc<JoinHandle<()>>>,
    server_task: Option<Arc<JoinHandle<()>>>,
    info: SessionInfo,
}

#[derive(Clone)]
pub struct SessionInfo {
    log: Logger,
    ifnum: i32,
    addr: Ipv6Addr,
    interval: u64,
    expire: u64,
    state: Arc<Mutex<State>>,
    host: String,
    server_addr: Ipv6Addr,
    server_port: u16,
    router_kind: RouterKind,
}

pub struct State {
    last_seen: Option<Instant>,
    hail_response_sent: bool,
    hail_response_received: bool,
}

impl State {
    fn new() -> Self {
        State {
            last_seen: None,
            hail_response_sent: false,
            hail_response_received: false,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize, JsonSchema)]
pub enum Status {
    NoContact,
    HailResponseSent,
    HailResponseReceived,
    Active,
    Expired,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        log: Logger,
        ifnum: i32,
        addr: Ipv6Addr,
        interval: u64,
        expire: u64,
        host: String,
        server_addr: Ipv6Addr,
        server_port: u16,
        router_kind: RouterKind,
    ) -> Self {
        Session {
            log: log.clone(),
            info: SessionInfo {
                log: log.clone(),
                ifnum,
                addr,
                interval,
                expire,
                state: Arc::new(Mutex::new(State::new())),
                host,
                server_addr,
                server_port,
                router_kind,
            },
            client_task: None,
            server_task: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        //
        // start peering server
        //

        self.server_task = Some(Arc::new(self.start_server()?));

        //
        // start peering client
        //

        self.client_task = Some(Arc::new(self.run()));

        Ok(())
    }

    pub async fn status(&self) -> Status {
        match self.info.state.lock().await.last_seen {
            Some(instant) => {
                if instant.elapsed().as_millis() > self.info.expire.into() {
                    Status::Expired
                } else {
                    Status::Active
                }
            }
            None => Status::NoContact,
        }
    }

    fn run(&self) -> JoinHandle<()> {
        let session = self.info.clone();
        spawn(async move {
            loop {
                trace!(session.log, "[{}] peer step", session.host);
                match Self::step(&session).await {
                    Ok(_) => {}
                    Err(e) => warn!(session.log, "{}", e),
                }
                trace!(
                    session.log,
                    "[{}] peer sleep {}",
                    session.host,
                    session.interval,
                );
                sleep(Duration::from_millis(session.interval)).await;
                trace!(session.log, "[{}] peer wake", session.host);
            }
        })
    }

    async fn step(session: &SessionInfo) -> Result<(), String> {
        let response = match Self::hail(&session).await {
            Ok(r) => r,
            Err(e) => {
                return Err(format!("hail: {}", e));
            }
        };
        if response.origin != session.host {
            return Err(format!("unexpected response: {:#?}", response));
        }

        let mut state = session.state.lock().await;
        state.last_seen = Some(Instant::now());
        state.hail_response_received = true;
        trace!(session.log, "updated last seen for {}", session.addr);
        Ok(())
    }

    async fn hail(s: &SessionInfo) -> Result<Response, String> {
        trace!(s.log, "sending hail to {}", s.addr);

        // XXX we need to use a custom hyper client here, and not a dropshot
        // generated client because hyper is the only rust client that supports
        // scoped ipv6 addresses. Dropshot uses reqwest internally which does
        // not support scoped ipv6 addresses.

        let msg = Hail {
            sender: s.host.clone(),
            router_kind: s.router_kind,
        };

        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

        let uri =
            format!("http://[{}%{}]:{}/hail", s.addr, s.ifnum, s.server_port,);

        let client = hyper::Client::new();
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&uri)
            .body(hyper::Body::from(json))
            .map_err(|e| e.to_string())?;

        let resp = client.request(req);

        let mut response = match timeout(Duration::from_millis(250), resp).await
        {
            Ok(resp) => match resp {
                Ok(r) => r,
                Err(e) => {
                    return Err(format!(
                        "hyper send request to {}: {}",
                        &uri, e,
                    ))
                }
            },
            Err(e) => {
                return Err(format!("peer request timeout to {}: {}", uri, e))
            }
        };

        let body = match response.body_mut().data().await {
            Some(body) => body.map_err(|e| e.to_string())?,
            None => return Err("no body found".to_string()),
        };

        let response: Response =
            serde_json::from_slice(body.as_ref()).map_err(|e| e.to_string())?;

        Ok(response)
    }

    fn start_server(&self) -> Result<JoinHandle<()>, String> {
        let sa = SocketAddrV6::new(
            self.info.server_addr,
            self.info.server_port,
            0,
            0,
        );
        let config = ConfigDropshot {
            bind_address: sa.into(),
            ..Default::default()
        };
        let log = ConfigLogging::StderrTerminal {
            level: ConfigLoggingLevel::Error,
        }
        .to_logger("peer")
        .map_err(|e| e.to_string())?;

        let mut api = ApiDescription::new();
        api.register(hail).unwrap();

        let context = HandlerContext {
            session: self.info.clone(),
        };

        let server = HttpServerStarter::new(&config, api, context, &log)
            .map_err(|e| format!("new peer dropshot: {}", e))?;

        info!(self.log, "peer: listening on {}", sa);

        let log = self.log.clone();
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
        info!(self.log, "dropping peer session for {}", self.info.addr);

        match self.client_task {
            Some(ref t) => t.abort(),
            None => {}
        }
        match self.server_task {
            Some(ref t) => t.abort(),
            None => {}
        }
    }
}

// Dropshot endpoints =========================================================

struct HandlerContext {
    session: SessionInfo,
}

#[endpoint {
    method = POST,
    path = "/hail"
}]
async fn hail(
    ctx: Arc<RequestContext<HandlerContext>>,
    rq: TypedBody<Hail>,
) -> Result<HttpResponseOk<Response>, HttpError> {
    let context = ctx.context();
    let session = &context.session;
    let msg = rq.into_inner();

    trace!(session.log, "received hail from {}", msg.sender);

    session.state.lock().await.hail_response_sent = true;

    Ok(HttpResponseOk(Response {
        sender: session.host.clone(),
        origin: msg.sender,
        router_kind: session.router_kind,
    }))
}

// Testing ====================================================================

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Result;
    use tokio::time::sleep;
    use util::test::testlab_x2;

    use crate::protocol::RouterKind;

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
            500,
            3000,
            "s1".into(),
            if0_v6,
            0x1dd0,
            RouterKind::Server,
        );

        let mut s2 = Session::new(
            log.clone(),
            if1.addr.info.index,
            if0_v6,
            500,
            3000,
            "s1".into(),
            if1_v6,
            0x1dd0,
            RouterKind::Server,
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

        sleep(Duration::from_secs(5)).await;

        assert_eq!(s1.status().await, Status::Active);
        assert_eq!(s2.status().await, Status::Active);
        println!("peering ok");

        //
        // drop a peer and test expiration
        //

        println!("testing expiration");
        drop(s2);
        sleep(Duration::from_millis(5000)).await;
        assert_eq!(s1.status().await, Status::Expired);

        Ok(())
    }
}
