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
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::spawn;
use std::time::Duration;

/// Context for Dropshot requests.
#[derive(Clone)]
pub struct BfdContext {
    /// The underlying deamon being run.
    daemon: Arc<Mutex<Daemon>>,
}

impl BfdContext {
    pub fn new(daemon: Arc<Mutex<Daemon>>) -> Self {
        Self { daemon }
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
    let rq = request.into_inner();

    if daemon.sessions.get(&rq.peer).is_some() {
        return Ok(HttpResponseUpdatedNoContent {});
    }

    let ch = channel(rq.listen, rq.peer, ctx.log.clone()).map_err(|e| {
        error!(ctx.log, "udp channel: {e}");
        HttpError::for_internal_error(e.to_string())
    })?;

    let timeout = Duration::from_micros(rq.required_rx);
    daemon.add_peer(rq.peer, timeout, rq.detection_threshold, ch);

    Ok(HttpResponseUpdatedNoContent {})
}

/// Request to remove a peer form the daemon.
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

/// Create a bidirectional chennel linking a peer session to an underlying BFD
/// session over UDP.
pub(crate) fn channel(
    listen: IpAddr,
    peer: IpAddr,
    log: Logger,
) -> Result<bidi::Endpoint<(IpAddr, packet::Control)>> {
    let domain = if listen.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sk = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let sa = SocketAddr::new(listen, BFD_MULTIHOP_PORT).into();
    sk.bind(&sa)?;

    let (local, remote) = bidi::channel();

    ingress(peer, remote.tx, sk.try_clone()?, log.clone());
    egress(remote.rx, sk, log.clone());

    Ok(local)
}

/// Run an egress handler, taking BFD control packets from a session and sending
/// the out to the peer over UDP.
fn egress(rx: Receiver<(IpAddr, packet::Control)>, sk: Socket, log: Logger) {
    spawn(move || loop {
        let (addr, pkt) = match rx.recv() {
            Ok(result) => result,
            Err(e) => {
                warn!(log, "udp egress channel closed: {e}");
                break;
            }
        };
        let sa = SocketAddr::new(addr, BFD_MULTIHOP_PORT).into();
        if let Err(e) = sk.send_to(&pkt.to_bytes(), &sa) {
            error!(log, "udp send: {e}");
        }
    });
}

/// Run an ingress handler, taking BFD control packets from a remote peer over
/// UDP and sending them to the local peer sesion for handling.
fn ingress(
    peer: IpAddr,
    tx: Sender<(IpAddr, packet::Control)>,
    sk: Socket,
    log: Logger,
) {
    spawn(move || loop {
        //TODO figure out real bound
        let mut buf = [MaybeUninit::new(0); 1024];

        let (n, sa) = match sk.recv_from(&mut buf) {
            Err(e) => {
                error!(log, "udp recv: {e}");
                continue;
            }
            Ok((n, sa)) => (n, sa.as_socket().unwrap()),
        };

        if sa.ip() != peer {
            warn!(
                log,
                "udp message not from peer {} != {peer}, dropping",
                sa.ip(),
            );
            continue;
        }

        // TODO: perhaps we don't need to use the socket2 crate here - this is
        // all pretty bog-standard UDP. Should probably switch to the UDP
        // machinery in the standard library.
        let ibuf = unsafe { &u8_slice_assume_init_ref(&buf)[..n] };

        let pkt = match packet::Control::wrap(ibuf) {
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
    });
}

//TODO trade for `MaybeUninit::slice_assume_init_ref` when it becomes available
//in stable Rust.
#[inline(always)]
pub(crate) const unsafe fn u8_slice_assume_init_ref(
    slice: &[MaybeUninit<u8>],
) -> &[u8] {
    unsafe { &*(slice as *const [MaybeUninit<u8>] as *const [u8]) }
}
