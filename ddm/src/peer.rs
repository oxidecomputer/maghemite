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
use crate::router::Config;

pub struct Session {
    pub log: Logger,
    pub client_task: Mutex<Option<Arc<JoinHandle<()>>>>,
    pub server_task: Mutex<Option<Arc<JoinHandle<()>>>>,
    pub info: SessionInfo,
    pub this_router_config: Config,
}

#[derive(Clone)]
pub struct SessionInfo {
    pub log: Logger,
    pub ifnum: i32,
    pub addr: Ipv6Addr,
    pub state: Arc<Mutex<State>>,
    pub host: Arc<Mutex<Option<String>>>,
    pub server_addr: Ipv6Addr,
    pub router_kind: Arc<Mutex<Option<RouterKind>>>,
}

impl SessionInfo {
    pub async fn status(&self, config: &Config) -> Status {
        match self.state.lock().await.last_seen {
            Some(instant) => {
                if instant.elapsed().as_millis() > config.peer_expire.into() {
                    Status::Expired
                } else {
                    Status::Active
                }
            }
            None => Status::NoContact,
        }
    }
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

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
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
        server_addr: Ipv6Addr,
        this_router_config: Config,
    ) -> Self {
        Session {
            log: log.clone(),
            info: SessionInfo {
                log: log.clone(),
                ifnum,
                addr,
                state: Arc::new(Mutex::new(State::new())),
                host: Arc::new(Mutex::new(None)),
                server_addr,
                router_kind: Arc::new(Mutex::new(None)),
            },
            client_task: Mutex::new(None),
            server_task: Mutex::new(None),
            this_router_config,
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        self.server_start().await?;
        self.client_start().await
    }

    pub async fn client_start(&self) -> Result<(), String> {
        *self.client_task.lock().await = Some(Arc::new(self.run()));
        Ok(())
    }

    pub async fn server_start(&self) -> Result<(), String> {
        *self.server_task.lock().await = Some(Arc::new(self.start_server()?));
        Ok(())
    }

    pub async fn status(&self) -> Status {
        match self.info.state.lock().await.last_seen {
            Some(instant) => {
                if instant.elapsed().as_millis()
                    > self.this_router_config.peer_expire.into()
                {
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
        let config = self.this_router_config.clone();
        spawn(async move {
            loop {
                trace!(session.log, "[{}] peer step", config.name);
                if let Err(e) = Self::step(&session, &config).await {
                    warn!(session.log, "{}", e);
                    if session.status(&config).await == Status::Expired {
                        warn!(
                            session.log,
                            "peer expired, dropping session for {}",
                            match *session.host.lock().await {
                                Some(ref x) => x,
                                None => "?",
                            },
                        );
                        break;
                    }
                }
                sleep(Duration::from_millis(config.peer_interval)).await;
                trace!(session.log, "[{}] peer wake", config.name);
            }
        })
    }

    async fn step(
        session: &SessionInfo,
        config: &Config,
    ) -> Result<(), String> {
        let response = match Self::hail(session, config).await {
            Ok(r) => r,
            Err(e) => {
                return Err(format!("hail: {}", e));
            }
        };
        if response.origin != config.name {
            return Err(format!("unexpected response: {:#?}", response));
        }

        let mut state = session.state.lock().await;
        state.last_seen = Some(Instant::now());
        state.hail_response_received = true;
        trace!(session.log, "updated last seen for {}", session.addr);
        Ok(())
    }

    async fn hail(
        s: &SessionInfo,
        config: &Config,
    ) -> Result<Response, String> {
        trace!(s.log, "sending hail to {}", s.addr);

        // XXX we need to use a custom hyper client here, and not a dropshot
        // generated client because hyper is the only rust client that supports
        // scoped ipv6 addresses. Dropshot uses reqwest internally which does
        // not support scoped ipv6 addresses.

        let msg = Hail {
            sender: config.name.clone(),
            router_kind: config.router_kind,
        };

        let json = serde_json::to_string(&msg).map_err(|e| e.to_string())?;

        let uri = format!(
            "http://[{}%{}]:{}/hail",
            s.addr, s.ifnum, config.peer_port,
        );

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
            self.this_router_config.peer_port,
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
            config: self.this_router_config.clone(),
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

        info!(self.log, "got runtime for session for {}", self.info.addr);

        futures::executor::block_on(async {
            if let Some(ref t) = *self.client_task.lock().await {
                t.abort();
            }
        });
        info!(self.log, "dropped client session for {}", self.info.addr);

        futures::executor::block_on(async {
            if let Some(ref t) = *self.server_task.lock().await {
                t.abort();
            }
        });
        info!(self.log, "dropped server session for {}", self.info.addr);
    }
}

// Dropshot endpoints =========================================================

struct HandlerContext {
    session: SessionInfo,
    config: Config,
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
    let config = &context.config;
    let msg = rq.into_inner();

    trace!(session.log, "received hail from {}", msg.sender);

    session.state.lock().await.hail_response_sent = true;
    *session.host.lock().await = Some(msg.sender.clone());
    *session.router_kind.lock().await = Some(msg.router_kind);

    Ok(HttpResponseOk(Response {
        sender: config.name.clone(),
        origin: msg.sender,
        router_kind: config.router_kind,
    }))
}

// Testing ====================================================================

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Result;
    use tokio::time::sleep;
    use util::test::testlab_x2;

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

        let config_s1 = Config {
            name: "s1".into(),
            peer_interval: 500,
            ..Default::default()
        };

        let config_s2 = Config {
            name: "s2".into(),
            peer_interval: 500,
            ..Default::default()
        };

        info!(log, "spicy");

        //
        // set up peer sessions
        //

        let s1 = Session::new(
            log.clone(),
            if0.addr.info.index,
            if1_v6,
            if0_v6,
            config_s1.clone(),
        );

        let s2 = Session::new(
            log.clone(),
            if1.addr.info.index,
            if0_v6,
            if1_v6,
            config_s2.clone(),
        );

        assert_eq!(s1.status().await, Status::NoContact);
        assert_eq!(s2.status().await, Status::NoContact);

        info!(log, "taco");

        //
        // run peer sessions
        //

        s1.start().await.expect("s1 start");
        s2.start().await.expect("s2 start");

        info!(log, "crunch");

        //
        // wait for peering
        //

        sleep(Duration::from_secs(5)).await;

        assert_eq!(s1.status().await, Status::Active);
        assert_eq!(s2.status().await, Status::Active);
        info!(log, "peering ok");

        //
        // drop a peer and test expiration
        //

        info!(log, "testing expiration");
        drop(s2);
        info!(log, "dropped session 2");
        sleep(Duration::from_millis(5000)).await;
        assert_eq!(s1.status().await, Status::Expired);

        Ok(())
    }
}
