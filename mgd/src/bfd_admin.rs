// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::HandlerContext, register};
use anyhow::Result;
use bfd::{bidi, packet, BfdPeerState, Daemon};
use dropshot::endpoint;
use dropshot::ApiDescription;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use rdb::BfdPeerConfig;
use rdb::SessionMode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, error, warn, Logger};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::UdpSocket;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread::spawn;
use std::thread::JoinHandle;
use std::time::Duration;

/// Context for Dropshot requests.
#[derive(Clone)]
pub struct BfdContext {
    /// The underlying deamon being run.
    pub(crate) daemon: Arc<Mutex<Daemon>>,
    dispatcher: Arc<Mutex<Dispatcher>>,
}

impl BfdContext {
    pub fn new(log: Logger) -> Self {
        Self {
            daemon: Arc::new(Mutex::new(Daemon::new(log.clone()))),
            dispatcher: Arc::new(Mutex::new(Dispatcher::new(log))),
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BfdPeerInfo {
    config: BfdPeerConfig,
    state: BfdPeerState,
}

pub(crate) fn api_description(api: &mut ApiDescription<Arc<HandlerContext>>) {
    register!(api, get_bfd_peers);
    register!(api, add_bfd_peer);
    register!(api, remove_bfd_peer);
}

/// Get all the peers and their associated BFD state. Peers are identified by IP
/// address.
#[endpoint { method = GET, path = "/bfd/peers" }]
pub(crate) async fn get_bfd_peers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<BfdPeerInfo>>, HttpError> {
    let mut result = Vec::new();
    for (addr, session) in
        ctx.context().bfd.daemon.lock().unwrap().sessions.iter()
    {
        result.push(BfdPeerInfo {
            config: BfdPeerConfig {
                peer: *addr,
                required_rx: session
                    .sm
                    .required_rx()
                    .as_micros()
                    .try_into()
                    .map_err(|_| {
                        HttpError::for_internal_error(String::from(
                            "required rx overflow",
                        ))
                    })?,
                detection_threshold: session.sm.detection_multiplier(),
                listen: ctx
                    .context()
                    .bfd
                    .dispatcher
                    .lock()
                    .unwrap()
                    .listen_addr_for_peer(addr)
                    .ok_or(HttpError::for_internal_error(format!(
                        "no listener for {addr}"
                    )))?,
                mode: session.mode,
            },
            state: session.sm.current(),
        });
    }

    Ok(HttpResponseOk(result))
}

/// Add a new peer to the daemon. A session for the specified peer will start
/// immediately.
#[endpoint { method = PUT, path = "/bfd/peers" }]
pub(crate) async fn add_bfd_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<BfdPeerConfig>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    add_peer(ctx.context().clone(), request.into_inner())?;
    Ok(HttpResponseUpdatedNoContent())
}

pub(crate) fn add_peer(
    ctx: Arc<HandlerContext>,
    rq: BfdPeerConfig,
) -> Result<(), HttpError> {
    let mut daemon = ctx.bfd.daemon.lock().unwrap();
    let dispatcher = ctx.bfd.dispatcher.clone();
    let db = ctx.db.clone();

    if daemon.sessions.get(&rq.peer).is_some() {
        return Ok(());
    }

    let (src_port, dst_port) = match rq.mode {
        SessionMode::SingleHop => {
            let offset: u16 =
                (daemon.sessions.len() % usize::from(u16::MAX)) as u16;
            (BFD_SINGLEHOP_SOURCE_PORT_BEGIN + offset, BFD_SINGLEHOP_PORT)
        }
        SessionMode::MultiHop => (0, BFD_MULTIHOP_PORT),
    };

    let ch = channel(
        dispatcher,
        rq.listen,
        rq.peer,
        src_port,
        dst_port,
        ctx.log.clone(),
    )
    .map_err(|e| {
        error!(ctx.log, "udp channel: {e}");
        HttpError::for_internal_error(e.to_string())
    })?;

    let timeout = Duration::from_micros(rq.required_rx);
    daemon.add_peer(rq.peer, timeout, rq.detection_threshold, rq.mode, ch, db);

    Ok(())
}

/// Request to remove a peer from the daemon.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
struct DeleteBfdPeerPathParams {
    /// Address of the peer to remove.
    pub addr: IpAddr,
}

/// Remove the specified peer from the daemon. The associated peer session will
/// be stopped immediately.
#[endpoint { method = DELETE, path = "/bfd/peers/{addr}" }]
pub(crate) async fn remove_bfd_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    params: Path<DeleteBfdPeerPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let rq = params.into_inner();
    ctx.context()
        .bfd
        .daemon
        .lock()
        .unwrap()
        .remove_peer(rq.addr);

    ctx.context()
        .bfd
        .dispatcher
        .lock()
        .unwrap()
        .remove(rq.addr)
        .map_err(|e| {
            error!(ctx.log, "failed to remove listener for {}: {e}", rq.addr);
            HttpError::for_internal_error(e.to_string())
        })?;

    Ok(HttpResponseUpdatedNoContent {})
}

/// Port to be used for BFD multihop per RFC 5883.
const BFD_MULTIHOP_PORT: u16 = 4784;
/// Port to be used for BFD single per RFC 5881.
const BFD_SINGLEHOP_PORT: u16 = 3784;
const BFD_SINGLEHOP_SOURCE_PORT_BEGIN: u16 = 49152;

/// Create a bidirectional channel linking a peer session to an underlying BFD
/// session over UDP.
pub(crate) fn channel(
    dispatcher: Arc<Mutex<Dispatcher>>,
    listen: IpAddr,
    peer: IpAddr,
    src_port: u16,
    dst_port: u16,
    log: Logger,
) -> Result<bidi::Endpoint<(IpAddr, packet::Control)>> {
    let (local, remote) = bidi::channel();

    // Ensure there is a dispatcher thread for this listening address and a
    // corresponding entry in the dispatcher table to send messages from `peer`
    // to the appropriate session via `remote.tx`.
    dispatcher.lock().unwrap().ensure(
        listen,
        peer,
        remote.tx,
        dst_port,
        log.clone(),
    )?;

    // Spawn an egress thread to take packets from the session and send them
    // out a UDP socket.
    egress(remote.rx, listen, src_port, dst_port, log.clone());

    Ok(local)
}

/// Run an egress handler, taking BFD control packets from a session and sending
/// them out to the peer over UDP.
fn egress(
    rx: Receiver<(IpAddr, packet::Control)>,
    local: IpAddr,
    src_port: u16,
    dst_port: u16,
    log: Logger,
) {
    spawn(move || loop {
        let (addr, pkt) = match rx.recv() {
            Ok(result) => result,
            Err(e) => {
                warn!(log, "udp egress channel closed: {e}");
                break;
            }
        };

        let sk = match UdpSocket::bind(SocketAddr::new(local, src_port)) {
            Err(e) => {
                error!(log, "failed to create tx socket: {e}");
                continue;
            }
            Ok(sk) => sk,
        };

        let sa = SocketAddr::new(addr, dst_port);
        if let Err(e) = sk.send_to(&pkt.to_bytes(), sa) {
            error!(log, "udp send: {e}");
        }
    });
}

type Sessions = HashMap<IpAddr, Sender<(IpAddr, packet::Control)>>;

#[derive(Debug)]
struct Listener {
    sk: UdpSocket,
    #[allow(dead_code)]
    handle: JoinHandle<()>,
    peers: HashSet<IpAddr>,
    kill_switch: Arc<AtomicBool>,
}

pub(crate) struct Dispatcher {
    // remote address -> session sender
    sessions: Arc<RwLock<Sessions>>,
    // local address -> listener thread
    listeners: HashMap<IpAddr, Listener>,

    log: Logger,
}

impl Dispatcher {
    pub fn new(log: Logger) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(Sessions::default())),
            listeners: HashMap::new(),
            log,
        }
    }
    pub fn listen_addr_for_peer(&self, peer: &IpAddr) -> Option<IpAddr> {
        for (addr, listener) in &self.listeners {
            for lpeer in &listener.peers {
                if lpeer == peer {
                    return Some(*addr);
                }
            }
        }
        debug!(self.log, "listeners: {:#?}", self.listeners);
        None
    }

    fn ensure(
        &mut self,
        local: IpAddr,
        remote: IpAddr,
        sender: Sender<(IpAddr, packet::Control)>,
        port: u16,
        log: Logger,
    ) -> Result<UdpSocket> {
        self.sessions.write().unwrap().insert(remote, sender);
        if let Some(ref mut listener) = self.listeners.get_mut(&local) {
            listener.peers.insert(remote);
            Ok(listener.sk.try_clone()?)
        } else {
            let sessions = self.sessions.clone();
            let sa = SocketAddr::new(local, port);
            let sk = UdpSocket::bind(sa)?;
            sk.set_read_timeout(Some(Duration::from_secs(1)))?;
            let skl = sk.try_clone()?;
            let mut peers = HashSet::new();
            peers.insert(remote);

            let kill_switch = Arc::new(AtomicBool::new(false));
            let ks = kill_switch.clone();

            self.listeners.insert(
                local,
                Listener {
                    sk: sk.try_clone()?,
                    handle: spawn(move || Self::listen(skl, sessions, ks, log)),
                    peers,
                    kill_switch,
                },
            );
            Ok(sk)
        }
    }

    fn remove(&mut self, peer: IpAddr) -> Result<()> {
        let mut to_remove = Vec::new();
        for (local, listener) in &mut self.listeners {
            if listener.peers.contains(&peer) {
                listener.peers.remove(&peer);
                if listener.peers.is_empty() {
                    listener
                        .kill_switch
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    to_remove.push(*local);
                }
            }
        }
        for x in &to_remove {
            self.listeners.remove(x);
        }
        self.sessions.write().unwrap().remove(&peer);
        Ok(())
    }

    fn listen(
        sk: UdpSocket,
        sessions: Arc<RwLock<Sessions>>,
        kill_switch: Arc<AtomicBool>,
        log: Logger,
    ) {
        loop {
            if kill_switch.load(std::sync::atomic::Ordering::Relaxed) {
                warn!(
                    log,
                    "kill switch activated for listener on {:?}",
                    sk.local_addr()
                );
                break;
            }
            // Maximum length of a BFD packet is on the order of 100 bytes (RFC
            // 5880).
            let mut buf = [0; 1024];

            let (n, sa) = match sk.recv_from(&mut buf) {
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        error!(log, "udp recv: {e}");
                    }
                    continue;
                }
                Ok((n, sa)) => (n, sa),
            };

            let guard = sessions.read().unwrap();
            let tx = match guard.get(&sa.ip()) {
                Some(tx) => tx,
                None => {
                    warn!(log, "unknown peer, dropping";
                        "peer" => sa.ip().to_string(),
                    );
                    continue;
                }
            };

            let pkt = match packet::Control::from_bytes(&buf[..n]) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!(log, "parse control packet: {e}";
                        "peer" => sa.ip().to_string(),
                    );
                    continue;
                }
            };

            if let Err(e) = tx.send((sa.ip(), pkt)) {
                warn!(log, "udp ingress channel closed: {e}";
                    "peer" => sa.ip().to_string(),
                );
                // This channel serves multiple peers, carry on as
                // the session associated with the closed channel
                // should get removed.
                continue;
            }
        }
    }
}
