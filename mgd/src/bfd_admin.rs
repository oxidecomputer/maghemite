// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use anyhow::Result;
use bfd::{bidi, packet, Daemon, PeerState};
use dropshot::endpoint;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{error, warn, Logger};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::net::{IpAddr, SocketAddr};
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
    daemon: Arc<Mutex<Daemon>>,
    dispatcher: Arc<Mutex<Dispatcher>>,
}

impl BfdContext {
    pub fn new(log: Logger) -> Self {
        Self {
            daemon: Arc::new(Mutex::new(Daemon::new(log.clone()))),
            dispatcher: Arc::new(Mutex::new(Dispatcher::default())),
        }
    }
}

/// Get all the peers and their associated BFD state. Peers are identified by IP
/// address.
#[endpoint { method = GET, path = "/bfd/peers" }]
pub(crate) async fn get_peers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<HashMap<IpAddr, PeerState>>, HttpError> {
    let result = ctx
        .context()
        .bfd
        .daemon
        .lock()
        .unwrap()
        .sessions
        .iter()
        .map(|(addr, session)| (*addr, session.sm.current()))
        .collect();

    Ok(HttpResponseOk(result))
}

/// Request to add a peer to the daemon.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct AddBfdPeerRequest {
    /// Address of the peer to add.
    pub peer: IpAddr,
    /// Address to listen on for control messages from the peer.
    pub listen: IpAddr,
    /// Acceptable time between control messages in microseconds.
    pub required_rx: u64,
    /// Detection threshold for connectivity as a multipler to required_rx
    pub detection_threshold: u8,
}

/// Add a new peer to the daemon. A session for the specified peer will start
/// immediately.
#[endpoint { method = PUT, path = "/bfd/peers" }]
pub(crate) async fn add_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddBfdPeerRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let mut daemon = ctx.context().bfd.daemon.lock().unwrap();
    let dispatcher = ctx.context().bfd.dispatcher.clone();
    let db = ctx.context().db.clone();
    let rq = request.into_inner();

    if daemon.sessions.get(&rq.peer).is_some() {
        return Ok(HttpResponseUpdatedNoContent {});
    }

    let ch = channel(dispatcher, rq.listen, rq.peer, ctx.log.clone()).map_err(
        |e| {
            error!(ctx.log, "udp channel: {e}");
            HttpError::for_internal_error(e.to_string())
        },
    )?;

    let timeout = Duration::from_micros(rq.required_rx);
    daemon.add_peer(rq.peer, timeout, rq.detection_threshold, ch, db);

    Ok(HttpResponseUpdatedNoContent {})
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
pub(crate) async fn remove_peer(
    ctx: RequestContext<Arc<HandlerContext>>,
    params: Path<DeleteBfdPeerPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let mut daemon = ctx.context().bfd.daemon.lock().unwrap();
    let rq = params.into_inner();

    daemon.remove_peer(rq.addr);

    Ok(HttpResponseUpdatedNoContent {})
}

/// Port to be used for BFD multihop per RFC 5883.
const BFD_MULTIHOP_PORT: u16 = 4784;

/// Create a bidirectional channel linking a peer session to an underlying BFD
/// session over UDP.
pub(crate) fn channel(
    dispatcher: Arc<Mutex<Dispatcher>>,
    listen: IpAddr,
    peer: IpAddr,
    log: Logger,
) -> Result<bidi::Endpoint<(IpAddr, packet::Control)>> {
    let (local, remote) = bidi::channel();

    // Ensure there is a dispatcher thread for this listening address and a
    // corresponding entry in the dispatcher table to send messages from `peer`
    // to the appropriate session via `remote.tx`.
    let sk = dispatcher.lock().unwrap().ensure(
        listen,
        peer,
        remote.tx,
        log.clone(),
    )?;

    // Spawn an egress thread to take packets from the session and send them
    // out a UDP socket.
    egress(remote.rx, sk, log.clone());

    Ok(local)
}

/// Run an egress handler, taking BFD control packets from a session and sending
/// the out to the peer over UDP.
fn egress(rx: Receiver<(IpAddr, packet::Control)>, sk: UdpSocket, log: Logger) {
    spawn(move || loop {
        let (addr, pkt) = match rx.recv() {
            Ok(result) => result,
            Err(e) => {
                warn!(log, "udp egress channel closed: {e}");
                break;
            }
        };
        let sa = SocketAddr::new(addr, BFD_MULTIHOP_PORT);
        if let Err(e) = sk.send_to(&pkt.to_bytes(), sa) {
            error!(log, "udp send: {e}");
        }
    });
}

type Sessions = HashMap<IpAddr, Sender<(IpAddr, packet::Control)>>;

#[derive(Default)]
pub(crate) struct Dispatcher {
    // remote address -> session sender
    sessions: Arc<RwLock<Sessions>>,
    // local address -> listener thread
    listeners: HashMap<IpAddr, (UdpSocket, JoinHandle<()>)>,
}

impl Dispatcher {
    fn ensure(
        &mut self,
        local: IpAddr,
        remote: IpAddr,
        sender: Sender<(IpAddr, packet::Control)>,
        log: Logger,
    ) -> Result<UdpSocket> {
        self.sessions.write().unwrap().insert(remote, sender);
        if let Some((sk, _)) = self.listeners.get(&local) {
            return Ok(sk.try_clone()?);
        }

        let sessions = self.sessions.clone();
        let sa = SocketAddr::new(local, BFD_MULTIHOP_PORT);
        let sk = UdpSocket::bind(sa)?;
        let skl = sk.try_clone()?;

        self.listeners.insert(
            local,
            (
                sk.try_clone()?,
                spawn(move || Self::listen(skl, sessions, log)),
            ),
        );

        Ok(sk)
    }

    fn listen(sk: UdpSocket, sessions: Arc<RwLock<Sessions>>, log: Logger) {
        loop {
            // Maximum length of a BFD packet is on the order of 100 bytes (RFC
            // 5880).
            let mut buf = [0; 1024];

            let (n, sa) = match sk.recv_from(&mut buf) {
                Err(e) => {
                    error!(log, "udp recv: {e}");
                    continue;
                }
                Ok((n, sa)) => (n, sa),
            };

            let guard = sessions.read().unwrap();
            let tx = match guard.get(&sa.ip()) {
                Some(tx) => tx,
                None => {
                    warn!(log, "unknown peer {}, dropping", sa.ip(),);
                    continue;
                }
            };

            let pkt = match packet::Control::wrap(&buf[..n]) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!(log, "parse control packet: {e}");
                    continue;
                }
            };

            if let Err(e) = tx.send((sa.ip(), pkt)) {
                warn!(log, "udp ingress channel closed: {e}");
                break;
            }
        }
    }
}
