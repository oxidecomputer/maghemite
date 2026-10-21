// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Runtime helpers for ddm router discovery: link-local UDPv6 sockets,
//! solicitation/advertisement loops, neighbor liveness, and the
//! [`handler`] entry point invoked by the routing state machine.
//! illumos-only.

use super::{DiscoveryError, Version};
use crate::sm::{Config, DiscoveryEvent, Event, PeerIdentity, SessionStats};
use crate::{dbg, err, inf, trc, wrn};
use ddm_api_types::db::RouterKind;
use serde::{Deserialize, Serialize};
use slog::Logger;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, Shutdown, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{
    Receiver, Sender, SyncSender, TrySendError, sync_channel,
};
use std::thread::{sleep, spawn};
use std::time::Instant;

const DDM_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xdd);
const DDM_PORT: u16 = 0xddd;
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 1 << 1;
/// Advertisements waiting for the neighbor thread. A peer advertises about
/// once per solicit interval and any one advertisement refreshes the neighbor,
/// so a short queue suffices; listeners drop advertisements when it is full
/// rather than letting a flood of packets grow it without bound.
const ADVERTISEMENT_QUEUE_DEPTH: usize = 16;

/// Reinterpret an initialized prefix of `[MaybeUninit<u8>]` as `[u8]`.
///
/// TODO: trade for `MaybeUninit::slice_assume_init_ref` when it stabilizes.
#[inline(always)]
const unsafe fn u8_slice_assume_init_ref(slice: &[MaybeUninit<u8>]) -> &[u8] {
    unsafe { &*(slice as *const [MaybeUninit<u8>] as *const [u8]) }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryPacket {
    version: u8,
    flags: u8,
    kind: RouterKind,
    #[serde(with = "ispf::str_lv8")]
    hostname: String,
}

impl DiscoveryPacket {
    fn new_solicitation(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: Version::V2 as u8,
            flags: SOLICIT,
            hostname,
            kind,
        }
    }

    fn new_advertisement(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: Version::V2 as u8,
            flags: ADVERTISE,
            hostname,
            kind,
        }
    }

    fn is_solicitation(&self) -> bool {
        (self.flags & SOLICIT) != 0
    }

    fn is_advertisement(&self) -> bool {
        (self.flags & ADVERTISE) != 0
    }
}

#[derive(Clone)]
struct DiscoveryHandlerContext {
    hostname: String,
    config: Config,
    mc_socket: Arc<Socket>,
    uc_socket: Arc<Socket>,
    advertisements: SyncSender<PeerIdentity>,
    log: Logger,
    event: Sender<Event>,
}

struct Neighbor {
    peer_id: PeerIdentity,
    last_seen: Instant,
    last_announced: Instant,
}

pub(crate) fn handler(
    hostname: String,
    config: Config,
    event: Sender<Event>,
    stats: Arc<SessionStats>,
    log: Logger,
) -> Result<Arc<AtomicBool>, DiscoveryError> {
    // listening on 2 sockets, solicitations are sent to DDM_MADDR, but
    // advertisements are sent to the unicast source addresses of a
    // solicitation. Binding to a link-scoped multicast address is required for
    // the interface passed in as scope_id to be honored. Listening on :: causes
    // chaos as all solicitations show up on all sockets.
    let mc = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    let uc = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    dbg!(log, config.if_name, "starting discovery handler");

    let mc_sa: SockAddr =
        SocketAddrV6::new(DDM_MADDR, DDM_PORT, 0, config.if_index).into();
    mc.set_reuse_address(true)?;
    mc.set_multicast_if_v6(config.if_index)?;
    mc.bind(&mc_sa)?;
    mc.join_multicast_v6(&DDM_MADDR, config.if_index)?;
    mc.set_multicast_loop_v6(false)?;
    mc.set_read_timeout(Some(config.discovery_read_timeout))?;

    let uc_sa: SockAddr =
        SocketAddrV6::new(config.addr, DDM_PORT, 0, config.if_index).into();
    uc.bind(&uc_sa)?;
    uc.set_read_timeout(Some(config.discovery_read_timeout))?;

    let (advertisements, advertisement_rx) =
        sync_channel(ADVERTISEMENT_QUEUE_DEPTH);
    let ctx = DiscoveryHandlerContext {
        mc_socket: Arc::new(mc),
        uc_socket: Arc::new(uc),
        advertisements,
        log: log.clone(),
        hostname,
        event,
        config,
    };

    let stop = Arc::new(AtomicBool::new(false));

    send_solicitations(ctx.clone(), stop.clone(), stats.clone());
    listen(
        ctx.clone(),
        ctx.mc_socket.clone(),
        stop.clone(),
        stats.clone(),
    )?;
    listen(
        ctx.clone(),
        ctx.uc_socket.clone(),
        stop.clone(),
        stats.clone(),
    )?;
    neighbor(ctx, advertisement_rx, stop.clone(), stats.clone());

    Ok(stop)
}

fn send_solicitations(
    ctx: DiscoveryHandlerContext,
    stop: Arc<AtomicBool>,
    stats: Arc<SessionStats>,
) {
    spawn(move || {
        loop {
            if stop.load(Ordering::Relaxed) {
                inf!(ctx.log, ctx.config.if_name, "stopping solicitor");
                break;
            }
            if let Err(e) = solicit(&ctx) {
                err!(ctx.log, ctx.config.if_name, "solicit failed: {}", e);
                stop.store(true, Ordering::Relaxed);
                break;
            }
            stats.solicitations_sent.fetch_add(1, Ordering::Relaxed);
            sleep(ctx.config.solicit_interval);
        }
    });
}

/// Own the neighbor state for this interface. Listener threads send each
/// advertisement here, so only this thread reads or writes the neighbor, and
/// advertise and expire events reach the state machine in the order this
/// thread decides on them.
///
/// Besides announcing a new or changed neighbor immediately, this re-announces
/// the current neighbor at most once per solicit interval, so a state machine
/// that left Exchange for Solicit while the neighbor is still present picks it
/// up again.
fn neighbor(
    ctx: DiscoveryHandlerContext,
    advertisements: Receiver<PeerIdentity>,
    stop: Arc<AtomicBool>,
    stats: Arc<SessionStats>,
) {
    spawn(move || {
        let mut nbr: Option<Neighbor> = None;
        loop {
            if let Ok(peer_id) =
                advertisements.recv_timeout(ctx.config.solicit_interval)
            {
                observe_neighbor(&ctx, &mut nbr, peer_id, &stats);
            }
            if let Some(n) = &mut nbr {
                let dt = Instant::now().duration_since(n.last_seen);
                if dt > ctx.config.expire_threshold {
                    wrn!(
                        &ctx.log,
                        ctx.config.if_name,
                        "neighbor {} expire",
                        &n.peer_id,
                    );
                    nbr = None;
                    stats.peer_expirations.fetch_add(1, Ordering::Relaxed);
                    emit_nbr_expire(&ctx);
                } else {
                    if dt > ctx.config.solicit_interval {
                        wrn!(
                            &ctx.log,
                            ctx.config.if_name,
                            "neighbor {} missed solicit interval",
                            &n.peer_id,
                        );
                    }
                    if n.last_announced.elapsed() >= ctx.config.solicit_interval
                    {
                        n.last_announced = Instant::now();
                        emit_nbr_update(&ctx, n.peer_id.clone());
                    }
                }
            }
            // We don't want to emit a solicit failure event until we drop the
            // handler context. Otherwise we could create a race on the discovery
            // sockets by trying to listen on a unicast address that a socket
            // waiting to be dropped is already listening on.
            if stop.load(Ordering::Relaxed) {
                inf!(
                    &ctx.log,
                    ctx.config.if_name,
                    "stopping discovery neighbor thread",
                );
                let event = ctx.event.clone();
                let log = ctx.log.clone();
                let if_name = ctx.config.if_name.clone();
                let wait = ctx.config.discovery_read_timeout;
                drop(ctx);
                // Ensure read handlers have registered the stop event.
                sleep(wait);
                emit_solicit_fail(event, log, &if_name);
                break;
            }
        }
    });
}

fn listen(
    ctx: DiscoveryHandlerContext,
    s: Arc<Socket>,
    stop: Arc<AtomicBool>,
    stats: Arc<SessionStats>,
) -> Result<(), DiscoveryError> {
    spawn(move || {
        loop {
            if let Some((addr, msg)) = recv(&ctx, &s) {
                handle_msg(&ctx, msg, &addr, &stats);
            };
            if stop.load(Ordering::Relaxed) {
                inf!(
                    &ctx.log,
                    ctx.config.if_name,
                    "stopping discovery handler"
                );
                if let Err(e) = s.shutdown(Shutdown::Both) {
                    wrn!(
                        &ctx.log,
                        ctx.config.if_name,
                        "failed to shut down discovery socket {e:?}",
                    );
                }
                break;
            }
        }
    });
    Ok(())
}

fn recv(
    ctx: &DiscoveryHandlerContext,
    s: &Arc<Socket>,
) -> Option<(Ipv6Addr, DiscoveryPacket)> {
    let mut buf = [MaybeUninit::new(0); 1024];
    let (n, sa) = match s.recv_from(&mut buf) {
        Err(e) => {
            if e.kind() != std::io::ErrorKind::WouldBlock {
                err!(
                    ctx.log,
                    ctx.config.if_name,
                    "discovery recv: {}",
                    e.kind()
                );
            }
            return None;
        }
        Ok(result) => result,
    };

    let addr = match sa.as_socket_ipv6() {
        Some(sa) => *sa.ip(),
        None => {
            err!(ctx.log, ctx.config.if_name, "non-v6 neighbor? {:?}", sa);
            return None;
        }
    };

    let ibuf = unsafe { &u8_slice_assume_init_ref(&buf)[..n] };

    let msg: DiscoveryPacket = match ispf::from_bytes_be(ibuf) {
        Ok(msg) => msg,
        Err(e) => {
            err!(ctx.log, ctx.config.if_name, "parse discovery msg {}", e);
            return None;
        }
    };

    trc!(ctx.log, ctx.config.if_name, "recv: {:?}", msg);

    Some((addr, msg))
}

fn handle_msg(
    ctx: &DiscoveryHandlerContext,
    msg: DiscoveryPacket,
    source_ip: &Ipv6Addr,
    stats: &Arc<SessionStats>,
) {
    if msg.is_solicitation() {
        handle_solicitation(ctx, source_ip, msg.hostname.clone(), stats);
    }

    if msg.is_advertisement() {
        let Ok(version) = Version::try_from(msg.version).inspect_err(|e| {
            err!(ctx.log, ctx.config.if_name, "unsupported DDM version: {e}");
        }) else {
            return;
        };
        let sender = PeerIdentity {
            addr: *source_ip,
            hostname: msg.hostname,
            kind: msg.kind,
            version,
        };
        handle_advertisement(ctx, sender, stats);
    }
}

fn handle_solicitation(
    ctx: &DiscoveryHandlerContext,
    sender: &Ipv6Addr,
    hostname: String,
    stats: &Arc<SessionStats>,
) {
    trc!(&ctx.log, ctx.config.if_name, "solicit from {}", hostname);
    stats.solicitations_received.fetch_add(1, Ordering::Relaxed);

    if let Err(e) = advertise(ctx, Some(*sender), stats) {
        err!(ctx.log, ctx.config.if_name, "icmp advertise: {}", e);
    }
}

fn handle_advertisement(
    ctx: &DiscoveryHandlerContext,
    peer_id: PeerIdentity,
    stats: &Arc<SessionStats>,
) {
    trc!(
        &ctx.log,
        ctx.config.if_name,
        "advert from {}",
        &peer_id.hostname
    );
    stats
        .advertisements_received
        .fetch_add(1, Ordering::Relaxed);

    match ctx.advertisements.try_send(peer_id) {
        Ok(()) => {}
        // The neighbor thread is behind. Dropping is safe because later
        // advertisements from the same peer carry the same information.
        Err(TrySendError::Full(peer_id)) => {
            inf!(
                ctx.log,
                ctx.config.if_name,
                "advertisement queue full, dropping advert from {peer_id}"
            );
        }
        Err(TrySendError::Disconnected(_)) => {
            err!(
                ctx.log,
                ctx.config.if_name,
                "send advertisement: neighbor thread exited"
            );
        }
    }
}

/// Record an advertisement from `peer_id`, telling the state machine when the
/// neighbor is new or has changed.
fn observe_neighbor(
    ctx: &DiscoveryHandlerContext,
    nbr: &mut Option<Neighbor>,
    peer_id: PeerIdentity,
    stats: &SessionStats,
) {
    match nbr {
        Some(nbr) => {
            if peer_id != nbr.peer_id {
                inf!(
                    ctx.log,
                    ctx.config.if_name,
                    "nbr {} -> {}",
                    nbr.peer_id,
                    peer_id
                );
                nbr.peer_id = peer_id.clone();
                // TODO: This name should be updated, but that requires oximeter
                //       schema changes. Do this when that becomes an option.
                stats.peer_address_changes.fetch_add(1, Ordering::Relaxed);
                nbr.last_announced = Instant::now();
                emit_nbr_update(ctx, peer_id);
            }
            nbr.last_seen = Instant::now();
        }
        None => {
            inf!(ctx.log, ctx.config.if_name, "nbr is {peer_id}",);
            *nbr = Some(Neighbor {
                peer_id: peer_id.clone(),
                last_seen: Instant::now(),
                last_announced: Instant::now(),
            });
            stats.peer_established.fetch_add(1, Ordering::Relaxed);
            emit_nbr_update(ctx, peer_id);
        }
    };
}

fn emit_nbr_update(ctx: &DiscoveryHandlerContext, peer: PeerIdentity) {
    if let Err(e) = ctx.event.send(DiscoveryEvent::Advertise(peer).into()) {
        err!(ctx.log, ctx.config.if_name, "send nbr event: {}", e);
    }
}

fn emit_nbr_expire(ctx: &DiscoveryHandlerContext) {
    if let Err(e) = ctx.event.send(DiscoveryEvent::Expire.into()) {
        err!(ctx.log, ctx.config.if_name, "send nbr expire: {}", e);
    }
}

fn emit_solicit_fail(event: Sender<Event>, log: Logger, if_name: &str) {
    if let Err(e) = event.send(DiscoveryEvent::SolicitFail.into()) {
        err!(log, if_name, "send solicit fail: {}", e);
    }
}

fn solicit(ctx: &DiscoveryHandlerContext) -> Result<usize, DiscoveryError> {
    let msg = DiscoveryPacket::new_solicitation(
        ctx.hostname.clone(),
        ctx.config.kind,
    );
    let data = ispf::to_bytes_be(&msg)?;
    let sa: SockAddr =
        SocketAddrV6::new(DDM_MADDR, DDM_PORT, 0, ctx.config.if_index).into();

    Ok(ctx.mc_socket.send_to(data.as_slice(), &sa)?)
}

fn advertise(
    ctx: &DiscoveryHandlerContext,
    dst: Option<Ipv6Addr>,
    stats: &Arc<SessionStats>,
) -> Result<usize, DiscoveryError> {
    let msg = DiscoveryPacket::new_advertisement(
        ctx.hostname.clone(),
        ctx.config.kind,
    );
    let data = ispf::to_bytes_be(&msg)?;
    let addr = match dst {
        Some(addr) => addr,
        None => DDM_MADDR,
    };
    let sa: SockAddr =
        SocketAddrV6::new(addr, DDM_PORT, 0, ctx.config.if_index).into();

    let n = ctx.uc_socket.send_to(data.as_slice(), &sa)?;
    stats.advertisements_sent.fetch_add(1, Ordering::Relaxed);
    Ok(n)
}
