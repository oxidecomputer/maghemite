// Copyright 2022 Oxide Computer Company

//! This file implements the ddm router discovery mechanisms. These mechanisims
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
//! response from piano, it updates the last seeen timestamp for piano. If at
//! some point piano stops responding to solicitations and the last seen
//! timestamp is older than the expiration threshold, violin will expire the
//! session and send out a notification to the ddm state machine that started
//! it. Violin will continue to send out solicitaions in case piano comes back.
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
//! version 1. The second byte is a flags bifield. The first position `S`
//! indicates a solicitation. The second position `A` indicates and
//! advertisement. All other positions are reserved for future use. The thrid
//! byte indicates the kind of router. Current values are 0 for a server router
//! and 1 for a transit routers. The fourth byte is a hostname length followed
//! directly by a hostname of up to 255 bytes in length.

use crate::db::{Db, PeerInfo, PeerStatus, RouterKind};
use crate::sm::{Config, Event, NeighborEvent};
use crate::util::u8_slice_assume_init_ref;
use crate::{dbg, err, inf, trc, wrn};
use serde::{Deserialize, Serialize};
use slog::Logger;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};
use thiserror::Error;

const DDM_MADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xdd);
const DDM_PORT: u16 = 0xddd;
const VERSION_1: u8 = 1;
const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 1 << 1;

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
            version: VERSION_1,
            flags: SOLICIT,
            hostname,
            kind,
        }
    }
    pub fn new_advertisement(hostname: String, kind: RouterKind) -> Self {
        Self {
            version: VERSION_1,
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
    config: Config,
    event: Sender<Event>,
    db: Db,
    log: Logger,
) -> Result<(), DiscoveryError> {
    // listening on 2 sockets, solicitations are sent to DDM_MADDR, but
    // advertisements are sent to the unicast source addresses of a
    // solicitation. Binding to a link-scoped multicast address is required for
    // the interface passed in as scope_id to be honored. Listening on :: causes
    // chaos as all solicitations show up on all sockets.
    let mc = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    let uc = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    dbg!(log, config.if_index, "starting discovery handler");

    let mc_sa: SockAddr =
        SocketAddrV6::new(DDM_MADDR, DDM_PORT, 0, config.if_index).into();
    mc.set_reuse_address(true)?;
    mc.set_multicast_if_v6(config.if_index)?;
    mc.bind(&mc_sa)?;
    mc.join_multicast_v6(&DDM_MADDR, config.if_index)?;
    mc.set_multicast_loop_v6(false)?;

    let uc_sa: SockAddr =
        SocketAddrV6::new(config.addr, DDM_PORT, 0, config.if_index).into();
    uc.bind(&uc_sa)?;

    let ctx = HandlerContext {
        mc_socket: Arc::new(mc),
        uc_socket: Arc::new(uc),
        nbr: Arc::new(RwLock::new(None)),
        log: log.clone(),
        hostname: hostname::get()?.to_string_lossy().to_string(),
        event,
        config,
        db,
    };

    send_solicitations(ctx.clone());
    listen(ctx.clone(), ctx.mc_socket.clone())?;
    listen(ctx.clone(), ctx.uc_socket.clone())?;
    expire(ctx)?;

    Ok(())
}

fn send_solicitations(ctx: HandlerContext) {
    spawn(move || loop {
        if let Err(e) = solicit(&ctx) {
            err!(ctx.log, ctx.config.if_index, "solicit failed: {}", e);
        }
        sleep(Duration::from_millis(ctx.config.solicit_interval));
    });
}

fn expire(ctx: HandlerContext) -> Result<(), DiscoveryError> {
    spawn(move || loop {
        let mut guard = match ctx.nbr.write() {
            Ok(nbr) => nbr,
            Err(e) => {
                err!(ctx.log, ctx.config.if_index, "lock nbr on expire: {}", e);
                return;
            }
        };
        if let Some(nbr) = &*guard {
            let dt = Instant::now().duration_since(nbr.last_seen);
            if dt.as_millis() > ctx.config.expire_threshold.into() {
                wrn!(
                    &ctx.log,
                    ctx.config.if_index,
                    "neighbor {}@{} expire",
                    &nbr.hostname,
                    nbr.addr
                );
                *guard = None;
                ctx.db.remove_peer(ctx.config.if_index);
                emit_nbr_expire(&ctx);
            } else if dt.as_millis() > ctx.config.solicit_interval.into() {
                wrn!(
                    &ctx.log,
                    ctx.config.if_index,
                    "neighbor {}@{} missed solicit interval",
                    &nbr.hostname,
                    nbr.addr
                );
            }
        }
        sleep(Duration::from_millis(ctx.config.solicit_interval));
    });
    Ok(())
}

fn listen(ctx: HandlerContext, s: Arc<Socket>) -> Result<(), DiscoveryError> {
    spawn(move || loop {
        if let Some((addr, msg)) = recv(&ctx, s.clone()) {
            handle_msg(&ctx, msg, &addr);
        };
    });
    Ok(())
}

fn recv(
    ctx: &HandlerContext,
    s: Arc<Socket>,
) -> Option<(Ipv6Addr, DiscoveryPacket)> {
    let mut buf = [MaybeUninit::new(0); 1024];
    let (n, sa) = match s.recv_from(&mut buf) {
        Err(e) => {
            err!(ctx.log, ctx.config.if_index, "icmp recv: {}", e);
            return None;
        }
        Ok(result) => result,
    };

    let addr = match sa.as_socket_ipv6() {
        Some(sa) => *sa.ip(),
        None => {
            err!(ctx.log, ctx.config.if_index, "non-v6 neighbor? {:?}", sa);
            return None;
        }
    };

    let ibuf = unsafe { &u8_slice_assume_init_ref(&buf)[..n] };

    let msg: DiscoveryPacket = match ispf::from_bytes_be(ibuf) {
        Ok(msg) => msg,
        Err(e) => {
            err!(ctx.log, ctx.config.if_index, "parse discovery msg {}", e);
            return None;
        }
    };

    trc!(ctx.log, ctx.config.if_index, "recv: {:?}", msg);

    Some((addr, msg))
}

fn handle_msg(ctx: &HandlerContext, msg: DiscoveryPacket, sender: &Ipv6Addr) {
    if msg.is_solicitation() {
        handle_solicitation(ctx, sender, msg.hostname.clone());
    }
    if msg.is_advertisement() {
        handle_advertisement(ctx, sender, msg.hostname, msg.kind);
    }
}

fn handle_solicitation(
    ctx: &HandlerContext,
    sender: &Ipv6Addr,
    hostname: String,
) {
    trc!(&ctx.log, ctx.config.if_index, "solicit from {}", hostname);

    if let Err(e) = advertise(ctx, Some(*sender)) {
        err!(ctx.log, ctx.config.if_index, "icmp advertise: {}", e);
    }
}

fn handle_advertisement(
    ctx: &HandlerContext,
    sender: &Ipv6Addr,
    hostname: String,
    kind: RouterKind,
) {
    trc!(&ctx.log, ctx.config.if_index, "advert from {}", &hostname);

    let mut guard = match ctx.nbr.write() {
        Ok(nbr) => nbr,
        Err(e) => {
            err!(ctx.log, ctx.config.if_index, "lock nbr on adv: {}", e);
            return;
        }
    };
    let mut current_nbr = match &mut *guard {
        Some(nbr) => nbr,
        None => {
            inf!(
                ctx.log,
                ctx.config.if_index,
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
            ctx.db.set_peer(
                ctx.config.if_index,
                PeerInfo {
                    status: PeerStatus::Active,
                    addr: *sender,
                    host: hostname,
                    kind,
                },
            );
            emit_nbr_update(ctx, sender);
            return;
        }
    };
    if *sender != current_nbr.addr {
        inf!(
            ctx.log,
            ctx.config.if_index,
            "nbr {}@{} {} -> {}@{} {}",
            current_nbr.hostname,
            current_nbr.addr,
            current_nbr.kind,
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
        ctx.db.set_peer(
            ctx.config.if_index,
            PeerInfo {
                status: PeerStatus::Active,
                addr: *sender,
                host: hostname,
                kind,
            },
        );
        emit_nbr_update(ctx, sender);
    } else {
        current_nbr.last_seen = Instant::now();
    }
}

fn emit_nbr_update(ctx: &HandlerContext, addr: &Ipv6Addr) {
    if let Err(e) = ctx.event.send(NeighborEvent::Advertise(*addr).into()) {
        err!(ctx.log, ctx.config.if_index, "send nbr event: {}", e);
    }
}

fn emit_nbr_expire(ctx: &HandlerContext) {
    if let Err(e) = ctx.event.send(NeighborEvent::Expire.into()) {
        err!(ctx.log, ctx.config.if_index, "send nbr expire: {}", e);
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

    Ok(ctx.uc_socket.send_to(data.as_slice(), &sa)?)
}
