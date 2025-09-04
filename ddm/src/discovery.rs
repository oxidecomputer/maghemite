// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This file implements the ddm router discovery mechanisms. These mechanisms
//! are responsible for three primary things
//!
//! 1. Soliciting other routers through UDP/IPv6 link local multicast.
//! 2. Sending out router advertisements in response to solicitations.
//! 3. Continuously soliciting link-local at a configurable rate to keep
//!    sessions alive and sending out notifications when peering arrangements
//!    expire due to not getting a solicitation response within a configurable
//!    time threshold.
//!
//! ## Protocol
//!
//! The general sequence of events is depicted in the following diagram.
//!
//!             *==========*                *==========*
//!             |  violin  |                |  piano   |
//!             *==========*                *==========*
//!                  |                           |
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |    advertise(fe80::47)    |
//!                  |<--------------------------|
//!                  |                           |
//!                  |            ...            |
//!                  |                           |
//!                  |                           |
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |    advertise(fe80::47)    |
//!                  |<--------------------------|
//!                  |                           |
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |                           |
//!             +----|                           |
//!      expire |    |                           |
//!       piano |    |                           |
//!             +--->|                           |
//!
//! This shows violin sending a link-local multicast solicitation over the wire.
//! That solicitation is received by piano and piano respons with an
//! advertisement to violin's link-local unicast address. From this point
//! forward solicitations and responses continue. Each time violin gets a
//! response from piano, it updates the last seen timestamp for piano. If at
//! some point piano stops responding to solicitations and the last seen
//! timestamp is older than the expiration threshold, violin will expire the
//! session and send out a notification to the ddm state machine that started
//! it. Violin will continue to send out solicitations in case piano comes back.
//!
//! In the event that piano undergoes renumbering e.g. it's link-local unicast
//! address changes, this will be detected by violin and an advertisement update
//! will be sent to the ddm state machine through the notification channel
//! provided to the discovery subsystem.
//!
//! The DDM discovery multicast address is ff02::dd. Discovery packets are sent
//! over UDP using port number 0xddd.
//!
//! ## Packets
//!
//! Discovery packets follow a very simple format
//!
//!                      1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   version     |S A r r r r r r|  router kind  | hostname len  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           hostname                            :
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! :                             ....                              :
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! The first byte indicates the version. The only valid version at present is
//! version 1. The second byte is a flags bitfield. The first position `S`
//! indicates a solicitation. The second position `A` indicates and
//! advertisement. All other positions are reserved for future use. The third
//! byte indicates the kind of router. Current values are 0 for a server router
//! and 1 for a transit routers. The fourth byte is a hostname length followed
//! directly by a hostname of up to 255 bytes in length.

use crate::db::Db;
use crate::sm::{Config, Event, NeighborEvent, SessionStats};
use crate::util::u8_slice_assume_init_ref;
use crate::{dbg, err, inf, trc, wrn};
use ddm_types::db::{PeerInfo, PeerStatus, RouterKind};
use mg_common::lock;
use serde::{Deserialize, Serialize};
use slog::Logger;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};
use thiserror::Error;

const DDM_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xdd);
const DDM_PORT: u16 = 0xddd;
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 1 << 1;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum Version {
    V2 = 2,
    V3 = 3,
}

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] ispf::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryPacket {
    version: u8,
    flags: u8,
    kind: RouterKind,
    #[serde(with = "ispf::str_lv8")]
    hostname: String,
}

impl DiscoveryPacket {
    pub fn new_solicitation(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: Version::V2 as u8,
            flags: SOLICIT,
            hostname,
            kind,
        }
    }
    pub fn new_advertisement(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: Version::V2 as u8,
            flags: ADVERTISE,
            hostname,
            kind,
        }
    }
    pub fn is_solicitation(&self) -> bool {
        (self.flags & SOLICIT) != 0
    }
    pub fn is_advertisement(&self) -> bool {
        (self.flags & ADVERTISE) != 0
    }
    pub fn set_solicitation(&mut self) {
        self.flags &= SOLICIT;
    }
    pub fn set_advertisement(&mut self) {
        self.flags &= ADVERTISE;
    }
}

#[derive(Clone)]
struct HandlerContext {
    hostname: String,
    config: Config,
    mc_socket: Arc<Socket>,
    uc_socket: Arc<Socket>,
    nbr: Arc<RwLock<Option<Neighbor>>>,
    log: Logger,
    event: Sender<Event>,
    db: Db,
}

struct Neighbor {
    addr: Ipv6Addr,
    hostname: String,
    kind: RouterKind,
    last_seen: Instant,
}

pub(crate) fn handler(
    hostname: String,
    config: Config,
    event: Sender<Event>,
    db: Db,
    stats: Arc<SessionStats>,
    log: Logger,
) -> Result<(), DiscoveryError> {
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
    mc.set_read_timeout(Some(Duration::from_millis(
        config.discovery_read_timeout,
    )))?;

    let uc_sa: SockAddr =
        SocketAddrV6::new(config.addr, DDM_PORT, 0, config.if_index).into();
    uc.bind(&uc_sa)?;
    uc.set_read_timeout(Some(Duration::from_millis(
        config.discovery_read_timeout,
    )))?;

    let ctx = HandlerContext {
        mc_socket: Arc::new(mc),
        uc_socket: Arc::new(uc),
        nbr: Arc::new(RwLock::new(None)),
        log: log.clone(),
        hostname,
        event,
        config,
        db,
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
    expire(ctx, stop, stats.clone())?;

    Ok(())
}

fn send_solicitations(
    ctx: HandlerContext,
    stop: Arc<AtomicBool>,
    stats: Arc<SessionStats>,
) {
    spawn(move || loop {
        if let Err(e) = solicit(&ctx) {
            err!(ctx.log, ctx.config.if_name, "solicit failed: {}", e);
            stop.store(true, Ordering::Relaxed);
            break;
        }
        stats.solicitations_sent.fetch_add(1, Ordering::Relaxed);
        sleep(Duration::from_millis(ctx.config.solicit_interval));
    });
}

fn expire(
    ctx: HandlerContext,
    stop: Arc<AtomicBool>,
    stats: Arc<SessionStats>,
) -> Result<(), DiscoveryError> {
    spawn(move || loop {
        let mut guard = match ctx.nbr.write() {
            Ok(nbr) => nbr,
            Err(e) => {
                err!(ctx.log, ctx.config.if_name, "lock nbr on expire: {}", e);
                return;
            }
        };
        if let Some(nbr) = &*guard {
            let dt = Instant::now().duration_since(nbr.last_seen);
            if dt.as_millis() > u128::from(ctx.config.expire_threshold) {
                wrn!(
                    &ctx.log,
                    ctx.config.if_name,
                    "neighbor {}@{} expire",
                    &nbr.hostname,
                    nbr.addr
                );
                *guard = None;
                stats.peer_expirations.fetch_add(1, Ordering::Relaxed);
                emit_nbr_expire(
                    ctx.event.clone(),
                    ctx.log.clone(),
                    &ctx.config.if_name,
                );
            } else if dt.as_millis() > u128::from(ctx.config.solicit_interval) {
                wrn!(
                    &ctx.log,
                    ctx.config.if_name,
                    "neighbor {}@{} missed solicit interval",
                    &nbr.hostname,
                    nbr.addr
                );
            }
        }
        drop(guard);
        // We don't want to emit a solicit failure event until we drop the
        // handler context. Otherwise we could create a race on the discovery
        // sockets by trying to listen on a unicast address that a socket
        // waiting to be dropped is already listening on.
        if stop.load(Ordering::Relaxed) {
            let event = ctx.event.clone();
            let log = ctx.log.clone();
            let if_name = ctx.config.if_name.clone();
            let wait = ctx.config.discovery_read_timeout;
            drop(ctx);
            // Ensure read handlers have registered the stop event.
            sleep(Duration::from_millis(wait));
            emit_solicit_fail(event, log, &if_name);
            break;
        }
        sleep(Duration::from_millis(ctx.config.solicit_interval));
    });
    Ok(())
}

fn listen(
    ctx: HandlerContext,
    s: Arc<Socket>,
    stop: Arc<AtomicBool>,
    stats: Arc<SessionStats>,
) -> Result<(), DiscoveryError> {
    spawn(move || loop {
        if let Some((addr, msg)) = recv(&ctx, &s) {
            handle_msg(&ctx, msg, &addr, &stats);
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
    });
    Ok(())
}

fn recv(
    ctx: &HandlerContext,
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
    ctx: &HandlerContext,
    msg: DiscoveryPacket,
    sender: &Ipv6Addr,
    stats: &Arc<SessionStats>,
) {
    if msg.is_solicitation() {
        handle_solicitation(ctx, sender, msg.hostname.clone(), stats);
    }
    if msg.is_advertisement() {
        handle_advertisement(
            ctx,
            sender,
            msg.hostname,
            msg.kind,
            msg.version,
            stats,
        );
    }
}

fn handle_solicitation(
    ctx: &HandlerContext,
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
    ctx: &HandlerContext,
    sender: &Ipv6Addr,
    hostname: String,
    kind: RouterKind,
    version: u8,
    stats: &Arc<SessionStats>,
) {
    trc!(&ctx.log, ctx.config.if_name, "advert from {}", &hostname);
    stats
        .advertisements_received
        .fetch_add(1, Ordering::Relaxed);

    // TODO: version negotiation
    //
    // Things currently work because ddm v1 does no version checking at all.
    // So ddm v2 speakers can send out discovery packets with the version set to
    // 2, and ddm v1 speakers can send out discovery packets with the version
    // set to 1, and as long a v2 router speaks version 1 after discovering a v1
    // peer, things will work. However, this will not work for version 3. So we
    // need to implement version negotiation. This would also not work for
    // changes in the discovery protocol, if we were to have changes there. So
    // we need to come up with a general way for both protocols to evolve.
    let version = match version {
        2 => Version::V2,
        3 => Version::V3,
        x => {
            err!(
                ctx.log,
                ctx.config.if_name,
                "unknown protocol version {}, known versions are: 1, 2",
                x
            );
            return;
        }
    };

    let mut guard = match ctx.nbr.write() {
        Ok(nbr) => nbr,
        Err(e) => {
            err!(ctx.log, ctx.config.if_name, "lock nbr on adv: {}", e);
            return;
        }
    };
    match &mut *guard {
        Some(nbr) => {
            if *sender != nbr.addr {
                inf!(
                    ctx.log,
                    ctx.config.if_name,
                    "nbr {}@{} {} -> {}@{} {}",
                    nbr.hostname,
                    nbr.addr,
                    nbr.kind,
                    sender,
                    hostname,
                    kind
                );
                nbr.last_seen = Instant::now();
                nbr.kind = kind;
                nbr.addr = *sender;
                stats.peer_address_changes.fetch_add(1, Ordering::Relaxed);
            }
            nbr.last_seen = Instant::now();
        }
        None => {
            inf!(
                ctx.log,
                ctx.config.if_name,
                "nbr is {}@{} {}",
                sender,
                hostname,
                kind
            );
            *guard = Some(Neighbor {
                addr: *sender,
                hostname: hostname.clone(),
                last_seen: Instant::now(),
                kind,
            });
            stats.peer_established.fetch_add(1, Ordering::Relaxed);
        }
    };
    drop(guard);
    let updated = ctx.db.set_peer(
        ctx.config.if_index,
        PeerInfo {
            status: PeerStatus::Active,
            addr: *sender,
            host: hostname,
            kind,
        },
    );
    if updated {
        lock!(stats.peer_address).replace(*sender);
        emit_nbr_update(ctx, sender, version);
    }
}

fn emit_nbr_update(ctx: &HandlerContext, addr: &Ipv6Addr, version: Version) {
    if let Err(e) = ctx
        .event
        .send(NeighborEvent::Advertise((*addr, version)).into())
    {
        err!(ctx.log, ctx.config.if_name, "send nbr event: {}", e);
    }
}

fn emit_nbr_expire(event: Sender<Event>, log: Logger, if_name: &str) {
    if let Err(e) = event.send(NeighborEvent::Expire.into()) {
        err!(log, if_name, "send nbr expire: {}", e);
    }
}

fn emit_solicit_fail(event: Sender<Event>, log: Logger, if_name: &str) {
    if let Err(e) = event.send(NeighborEvent::SolicitFail.into()) {
        err!(log, if_name, "send solicit fail: {}", e);
    }
}

fn solicit(ctx: &HandlerContext) -> Result<usize, DiscoveryError> {
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
    ctx: &HandlerContext,
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
