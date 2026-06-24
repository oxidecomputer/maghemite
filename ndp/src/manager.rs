// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::packet::{Icmp6RouterAdvertisement, Icmp6RouterSolicitation};
use crate::util::{
    DropSleep, ListeningSocketError, ReceivedRouterAdvertisement,
    create_socket, send_ra, send_rs,
};
use mg_common::lock;
use mg_common::thread::ManagedThread;
use slog::{Logger, debug, error};
use socket2::Socket;
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, sleep};
use std::time::{Duration, Instant};

/// The `RouterDiscovery` worker runs router discovery for an individual interface.
///
/// Discovery is started on construction and stopped automatically when the
/// worker is dropped via the `ManagedThread` Drop implementation.
#[derive(Debug)]
pub struct RouterDiscoveryThreads {
    /// Handle to the transmit loop thread
    _tx_thread: Arc<ManagedThread>,
    /// Handle to the receive loop thread
    _rx_thread: Arc<ManagedThread>,
}

#[derive(Debug, thiserror::Error)]
pub enum NewRouterDiscoveryError {
    #[error("socket create: {0}")]
    SocketCreate(ListeningSocketError),

    #[error("socket clone: {0}")]
    SocketClone(std::io::Error),

    #[error("thread spawn error: {0}")]
    ThreadSpawn(std::io::Error),
}

/// Runtime state for router discovery on an interface.
#[derive(Debug, Clone)]
pub struct RouterDiscoveryRuntimeState {
    /// Whether the TX loop thread is running
    pub tx_running: bool,
    /// Whether the RX loop thread is running
    pub rx_running: bool,
}

impl RouterDiscoveryThreads {
    /// Query the current state of the rx/tx threads for this interface.
    pub fn get_runtime_state(&self) -> RouterDiscoveryRuntimeState {
        RouterDiscoveryRuntimeState {
            tx_running: self._tx_thread.is_running(),
            rx_running: self._rx_thread.is_running(),
        }
    }

    /// Start router discovery for a given interface.
    pub fn start(
        ifx: Ipv6NetworkInterface,
        state: Arc<RouterDiscoveryState>,
        log: Logger,
    ) -> Result<Self, NewRouterDiscoveryError> {
        let sk = create_socket(ifx.scope_id)
            .map_err(NewRouterDiscoveryError::SocketCreate)?;

        let ifname = ifx.name.clone();

        let tx_thread = Arc::new(ManagedThread::new());
        let tx_dropped = tx_thread.dropped_flag();
        tx_thread.start({
            let sk = sk
                .try_clone()
                .map_err(NewRouterDiscoveryError::SocketClone)?;
            let ifx = ifx.clone();
            let state = Arc::clone(&state);
            let log = log.clone();
            Builder::new()
                .name(format!("ndp_tx_{ifname}"))
                .spawn(move || tx_loop(sk, ifx, state, log, tx_dropped))
                .map_err(NewRouterDiscoveryError::ThreadSpawn)?
        });

        let rx_thread = Arc::new(ManagedThread::new());
        let rx_dropped = rx_thread.dropped_flag();
        rx_thread.start({
            let sk = sk
                .try_clone()
                .map_err(NewRouterDiscoveryError::SocketClone)?;
            let ifx = ifx.clone();
            let state = Arc::clone(&state);
            let log = log.clone();
            Builder::new()
                .name(format!("ndp_rx_{ifname}"))
                .spawn(move || rx_loop(sk, ifx, state, log, rx_dropped))
                .map_err(NewRouterDiscoveryError::ThreadSpawn)?
        });

        Ok(Self {
            _tx_thread: tx_thread,
            _rx_thread: rx_thread,
        })
    }
}

/// Run the router discovery receive loop. Advertisements are used to set the
/// current peer address. Advertisements are sent in response to solicitations.
///
/// A read timeout of 1 second is used. When the time out hits instead of
/// receiving a advertisement or solicitation packet, the current neighbor (if
/// any) is checked for expiration.
fn rx_loop(
    s: Socket,
    ifx: Ipv6NetworkInterface,
    state: Arc<RouterDiscoveryState>,
    log: Logger,
    dropped: Arc<AtomicBool>,
) {
    const INTERVAL: Duration = Duration::from_secs(1);
    loop {
        if dropped.load(Ordering::SeqCst) {
            break;
        }
        let _ds = DropSleep(INTERVAL);

        let mut buf: [MaybeUninit<u8>; 1024] =
            [const { MaybeUninit::uninit() }; 1024];

        match s.recv_from(&mut buf) {
            Ok((len, src)) => {
                let buf: &[u8] = unsafe {
                    std::slice::from_raw_parts(buf.as_ptr().cast(), len)
                };
                let Some(src) = src.as_socket_ipv6().map(|x| *x.ip()) else {
                    continue;
                };
                if let Ok(ra) = Icmp6RouterAdvertisement::from_wire(buf) {
                    handle_ra(&ifx, &state, &log, ra, src);
                }
                if let Ok(rs) = Icmp6RouterSolicitation::from_wire(buf) {
                    handle_rs(&s, &ifx, &state, &log, rs, src);
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    check_expired(&state);
                    continue;
                }
                error!(log, "rx: {e}");
            }
        }
    }
}

/// Start the transmit loop, periodically sending out announcements.
fn tx_loop(
    sk: Socket,
    ifx: Ipv6NetworkInterface,
    state: Arc<RouterDiscoveryState>,
    log: Logger,
    dropped: Arc<AtomicBool>,
) {
    const INTERVAL: Duration = Duration::from_secs(5);
    loop {
        if dropped.load(Ordering::SeqCst) {
            break;
        }
        send_ra(
            &sk,
            ifx.ip,
            None,
            ifx.scope_id,
            state.get_tx_router_lifetime(),
            &log,
        );
        send_rs(&sk, ifx.ip, None, ifx.scope_id, &log);
        sleep(INTERVAL);
    }
}

/// Handle a router advertisement. On reception the neighbor source address is
/// updated as well as the time of reception and the stored advertisement
/// containing the reachable time.
fn handle_ra(
    ifx: &Ipv6NetworkInterface,
    state: &RouterDiscoveryState,
    log: &Logger,
    ra: Icmp6RouterAdvertisement,
    src: Ipv6Addr,
) {
    // Per RFC 4861 Section 6.1.2: a valid RA's source is always link-local
    if !src.is_unicast_link_local() {
        debug!(
            log,
            "ignoring RA from non-link-local source {src} on {}", ifx.name,
        );
        return;
    }

    state.record_advertisement(ra, src);
}

/// Handle a router solicitation by sending an announcement to the sender.
fn handle_rs(
    sk: &Socket,
    ifx: &Ipv6NetworkInterface,
    state: &RouterDiscoveryState,
    log: &Logger,
    // Don't really care what's in the solicitation for now, just
    // care that it parses as a valid RS.
    _rs: Icmp6RouterSolicitation,
    src: Ipv6Addr,
) {
    send_ra(
        sk,
        ifx.ip,
        Some(src),
        ifx.scope_id,
        state.get_tx_router_lifetime(),
        log,
    );
}

/// Check to see if the reachable time for our current peer (if any) is expired.
/// If so, remove the peer.
fn check_expired(state: &RouterDiscoveryState) {
    state.clear_expired_neighbor();
}

/// IPv6 link-local interface used for router discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6NetworkInterface {
    /// Interface's name
    pub name: String,
    /// Interface's address
    pub ip: Ipv6Addr,
    /// IPv6 scope ID (interface index)
    pub scope_id: NonZeroU32,
}

/// Detailed information about a discovered peer on an interface.
#[derive(Debug, Clone)]
pub struct RouterAdvertisementInfo {
    /// The peer's IPv6 address
    pub address: Ipv6Addr,
    /// When the peer was first discovered
    pub first_seen: Instant,
    /// When the most recent Router Advertisement was received
    pub last_seen: Instant,
    /// Router lifetime from the RA
    pub router_lifetime: u16,
    /// Reachable time from the RA
    pub reachable_time: u32,
    /// Reachable time used by the discovery runtime
    pub effective_reachable_time: Duration,
    /// Retransmit timer from the RA
    pub retrans_timer: u32,
    /// Whether the peer has expired
    pub expired: bool,
}

#[derive(Debug)]
pub struct RouterDiscoveryState {
    neighbor: Mutex<Option<ReceivedRouterAdvertisement>>,
    tx_router_lifetime: AtomicU16,
}

impl RouterDiscoveryState {
    pub fn new(tx_router_lifetime: u16) -> Self {
        Self {
            neighbor: Mutex::new(None),
            tx_router_lifetime: AtomicU16::new(tx_router_lifetime),
        }
    }

    pub fn set_tx_router_lifetime(&self, tx_router_lifetime: u16) {
        self.tx_router_lifetime
            .store(tx_router_lifetime, Ordering::Relaxed);
    }

    pub fn get_tx_router_lifetime(&self) -> u16 {
        self.tx_router_lifetime.load(Ordering::Relaxed)
    }

    pub fn discovered_neighbor(&self) -> Option<Ipv6Addr> {
        let guard = lock!(self.neighbor);
        let neighbor = guard.as_ref()?;
        if neighbor.expired() {
            None
        } else {
            Some(neighbor.source)
        }
    }

    pub fn discovered_neighbor_info(&self) -> Option<RouterAdvertisementInfo> {
        let guard = lock!(self.neighbor);
        guard.as_ref().map(|neighbor| RouterAdvertisementInfo {
            address: neighbor.source,
            first_seen: neighbor.first_seen,
            last_seen: neighbor.last_seen,
            router_lifetime: neighbor.advertisement.lifetime,
            reachable_time: neighbor.advertisement.reachable_time,
            effective_reachable_time: neighbor
                .advertisement
                .effective_reachable_time(),
            retrans_timer: neighbor.advertisement.retrans_timer,
            expired: neighbor.expired(),
        })
    }

    pub fn record_advertisement(
        &self,
        advertisement: Icmp6RouterAdvertisement,
        source: Ipv6Addr,
    ) {
        let mut guard = lock!(self.neighbor);
        let now = Instant::now();
        let first_seen = guard
            .as_ref()
            .filter(|prev| prev.source == source)
            .map(|prev| prev.first_seen)
            .unwrap_or(now);

        *guard = Some(ReceivedRouterAdvertisement {
            first_seen,
            last_seen: now,
            advertisement,
            source,
        });
    }

    pub fn clear_neighbor(&self) {
        *lock!(self.neighbor) = None;
    }

    pub fn clear_expired_neighbor(&self) {
        let mut guard = lock!(self.neighbor);
        if guard.as_ref().is_some_and(|neighbor| neighbor.expired()) {
            *guard = None;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::packet::{Icmp6RouterAdvertisement, Icmp6RouterSolicitation};
    use crate::util::{ALL_NODES_MCAST, ALL_ROUTERS_MCAST, cksum};
    use std::net::Ipv6Addr;

    #[test]
    fn router_solicitation_checksum_uses_all_routers_multicast() {
        let src = "fe80::1".parse().unwrap();
        let mut data = ispf::to_bytes_be(&Icmp6RouterSolicitation::default())
            .expect("serialize router solicitation");

        cksum(src, Some(ALL_ROUTERS_MCAST), 8, &mut data);

        assert_eq!(&data[2..4], &[0x7d, 0x36]);
    }

    #[test]
    fn router_advertisement_checksum_defaults_to_all_nodes_multicast() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut default_dst =
            ispf::to_bytes_be(&Icmp6RouterAdvertisement::default())
                .expect("serialize router advertisement");
        let mut all_nodes_dst = default_dst.clone();

        cksum(src, None, 16, &mut default_dst);
        cksum(src, Some(ALL_NODES_MCAST), 16, &mut all_nodes_dst);

        assert_eq!(default_dst[2..4], all_nodes_dst[2..4]);
    }

    #[test]
    fn router_solicitation_with_link_layer_addr() {
        // Attempt to parse an ICMPv6 router solicitation with a link-layer
        // address as a router advertisement. This should produce an error. It
        // should not successfully parse, and it should not panic.
        //
        //     0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |     Code      |          Checksum             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                            Reserved                           |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |    Length     |    Link-Layer Address ...
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //           .... Link-Layer address                               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let data: [u8; 16] = [
            133, 0, 11, 22, // type, code checksum
            0, 0, 0, 0, // reserved
            1, 1, 0xab, 0xbb, // Link layer addr
            0xcc, 0xdd, 0xee, 0xff,
        ];

        Icmp6RouterAdvertisement::from_wire(&data)
            .expect_err("RS should not parse as RA");
        Icmp6RouterSolicitation::from_wire(&data).expect("parsed solicitation");
    }

    #[test]
    fn minimum_router_solicitation() {
        // Attempt to parse a minimal ICMPv6 router solicitation as a
        // router advertisement. This should produce an error. It should not
        // successfully parse, and it should not panic.
        //
        //     0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |     Code      |          Checksum             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                            Reserved                           |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let data: [u8; 8] = [133, 0, 11, 22, 0, 0, 0, 0];
        Icmp6RouterAdvertisement::from_wire(&data)
            .expect_err("RS should not parse as RA");
        Icmp6RouterSolicitation::from_wire(&data).expect("parsed solicitation");
    }

    #[test]
    fn minimum_router_advertisement() {
        // Attempt to parse a minimal ICMPv6 router advertisement as a
        // router solicitation. This should produce an error. It should not
        // successfully parse, and it should not panic.
        //
        //     0                   1                   2                   3
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |     Type      |     Code      |          Checksum             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                         Reachable Time                        |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                          Retrans Timer                        |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        let data: [u8; 16] = [
            134, 0, 11, 22, // type, code, checksum
            255, 0, 0, 30, // hop limit, flags, lifetime
            0, 0, 0, 0, // reachable time
            0, 0, 0, 0, // retrans timer
        ];
        Icmp6RouterSolicitation::from_wire(&data)
            .expect_err("RA should not parse as RS");
        Icmp6RouterAdvertisement::from_wire(&data)
            .expect("parsed advertisement");
    }
}
