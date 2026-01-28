// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::packet::{Icmp6RouterAdvertisement, Icmp6RouterSolicitation};
use crate::util::{
    DropSleep, ListeningSocketError, ReceivedAdvertisement, create_socket,
    send_ra, send_rs,
};
use mg_common::thread::ManagedThread;
use mg_common::{lock, read_lock, write_lock};
use slog::{Logger, error};
use socket2::Socket;
use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{Builder, sleep};
use std::time::{Duration, Instant};

/// The `NdpManager` performs router discovery for a provided set of interfaces.
///
/// Use `add_interface` and `remove_interface` to manage discovery interfaces and
/// use `get_peer` to determine if a router peer has been discovered for a given
/// interface.
#[derive(Debug)]
pub struct NdpManager {
    /// Individual interface-level NDP managers.
    interfaces: RwLock<Vec<Arc<InterfaceNdpManager>>>,
    log: Logger,
}

impl NdpManager {
    /// Create a new NDP manager.
    pub fn new(log: Logger) -> Arc<Self> {
        Arc::new(Self {
            interfaces: RwLock::new(Vec::default()),
            log,
        })
    }

    /// Add an interface to the NDP manager. Discovery starts immediately.
    pub fn add_interface(
        &self,
        ifx: Ipv6NetworkInterface,
        router_lifetime: u16,
    ) -> Result<(), NewInterfaceNdpManagerError> {
        write_lock!(self.interfaces).push(InterfaceNdpManager::new(
            ifx,
            router_lifetime,
            self.log.clone(),
        )?);
        Ok(())
    }

    /// Remove an interface from the NDP manager. Discovery is stopped when
    /// the interface is removed.
    pub fn remove_interface(&self, ifx: Ipv6NetworkInterface) -> bool {
        let mut ifxs_guard = write_lock!(self.interfaces);
        let Some(pos) = ifxs_guard.iter().position(|x| x.inner.ifx == ifx)
        else {
            return false;
        };

        ifxs_guard.remove(pos);
        true
    }

    /// Get a router peer, if any, that has been discovered for the given interface.
    pub fn get_peer(&self, ifx: &Ipv6NetworkInterface) -> Option<Ipv6Addr> {
        let ifxs_guard = read_lock!(self.interfaces);
        let interface = ifxs_guard.iter().find(|x| &x.inner.ifx == ifx)?;
        let nbr_guard = lock!(interface.inner.neighbor_router);
        let neighbor_router = nbr_guard.as_ref()?;

        if neighbor_router.expired() {
            None
        } else {
            Some(neighbor_router.sender)
        }
    }

    /// Get detailed information about a discovered peer for a specific interface.
    ///
    /// Returns full advertisement details including timestamps and RA parameters,
    /// even if the peer has expired. Returns None only if no peer was ever discovered.
    pub fn get_peer_detail(
        &self,
        ifx: &Ipv6NetworkInterface,
    ) -> Option<PeerAdvertisementInfo> {
        let ifxs_guard = read_lock!(self.interfaces);
        let interface = ifxs_guard.iter().find(|x| &x.inner.ifx == ifx)?;
        let nbr_guard = lock!(interface.inner.neighbor_router);
        let neighbor_router = nbr_guard.as_ref()?;

        Some(PeerAdvertisementInfo {
            address: neighbor_router.sender,
            first_seen: neighbor_router.first_seen,
            when: neighbor_router.when,
            router_lifetime: neighbor_router.adv.lifetime,
            reachable_time: neighbor_router.adv.reachable_time,
            retrans_timer: neighbor_router.adv.retrans_timer,
            expired: neighbor_router.expired(),
        })
    }

    /// List all interfaces managed by NDP with their detailed state.
    ///
    /// Returns information about each interface including local address,
    /// advertised router lifetime, and discovered peer details (if any).
    pub fn list_interfaces_detailed(&self) -> Vec<InterfaceAdvertisementInfo> {
        let ifxs_guard = read_lock!(self.interfaces);
        ifxs_guard
            .iter()
            .map(|iface_mgr| {
                let nbr_guard = lock!(iface_mgr.inner.neighbor_router);
                let discovered_peer =
                    nbr_guard.as_ref().map(|adv| PeerAdvertisementInfo {
                        address: adv.sender,
                        first_seen: adv.first_seen,
                        when: adv.when,
                        router_lifetime: adv.adv.lifetime,
                        reachable_time: adv.adv.reachable_time,
                        retrans_timer: adv.adv.retrans_timer,
                        expired: adv.expired(),
                    });

                InterfaceAdvertisementInfo {
                    interface: iface_mgr.inner.ifx.clone(),
                    router_lifetime: iface_mgr.inner.router_lifetime,
                    discovered_peer,
                }
            })
            .collect()
    }
}

/// The `InterfaceNdpManager` runs router discovery for an individual interface.
///
/// Discovery is started on construction and stopped automatically when the
/// interface manager is dropped via the `ManagedThread` Drop implementation.
#[derive(Debug)]
pub struct InterfaceNdpManager {
    /// Handle to the transmit loop thread
    _tx_thread: Arc<ManagedThread>,
    /// Handle to the receive loop thread
    _rx_thread: Arc<ManagedThread>,
    inner: InterfaceNdpManagerInner,
}

#[derive(Debug, Clone)]
struct InterfaceNdpManagerInner {
    ifx: Ipv6NetworkInterface,
    neighbor_router: Arc<Mutex<Option<ReceivedAdvertisement>>>,
    router_lifetime: u16,
    log: Logger,
}

#[derive(Debug, thiserror::Error)]
pub enum NewInterfaceNdpManagerError {
    #[error("socket create: {0}")]
    SocketCreate(ListeningSocketError),

    #[error("socket clone: {0}")]
    SocketClone(std::io::Error),

    #[error("thread spawn error: {0}")]
    ThreadSpawn(std::io::Error),
}

impl InterfaceNdpManager {
    /// Create a new interface manager for a given interface.
    pub fn new(
        ifx: Ipv6NetworkInterface,
        router_lifetime: u16,
        log: Logger,
    ) -> Result<Arc<Self>, NewInterfaceNdpManagerError> {
        let sk = create_socket(ifx.index)
            .map_err(NewInterfaceNdpManagerError::SocketCreate)?;

        let ifname = ifx.name.clone();

        let inner = InterfaceNdpManagerInner {
            ifx,
            neighbor_router: Arc::new(Mutex::new(None)),
            router_lifetime,
            log,
        };

        let tx_thread = Arc::new(ManagedThread::new());
        let tx_dropped = tx_thread.dropped_flag();
        tx_thread.start({
            let sk = sk
                .try_clone()
                .map_err(NewInterfaceNdpManagerError::SocketClone)?;
            let s = inner.clone();
            Builder::new()
                .name(format!("ndp_tx_{ifname}"))
                .spawn(move || s.tx_loop(sk, tx_dropped))
                .map_err(NewInterfaceNdpManagerError::ThreadSpawn)?
        });

        let rx_thread = Arc::new(ManagedThread::new());
        let rx_dropped = rx_thread.dropped_flag();
        rx_thread.start({
            let sk = sk
                .try_clone()
                .map_err(NewInterfaceNdpManagerError::SocketClone)?;
            let s = inner.clone();
            Builder::new()
                .name(format!("ndp_rx_{ifname}"))
                .spawn(move || s.rx_loop(sk, rx_dropped))
                .map_err(NewInterfaceNdpManagerError::ThreadSpawn)?
        });

        Ok(Arc::new(Self {
            _tx_thread: tx_thread,
            _rx_thread: rx_thread,
            inner,
        }))
    }
}

impl InterfaceNdpManagerInner {
    /// Run the interface NDP manager receive loop. Advertisements are used to
    /// set the current peer address. Advertisements are sent in response to
    /// solicitations.
    ///
    /// A read timeout of 1 second is used. When the time out hits instead of
    /// receiving a advertisement or solicitation packet, the current neighbor
    /// (if any) is checked for expiration.
    pub fn rx_loop(&self, s: Socket, dropped: Arc<AtomicBool>) {
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
                    let Some(src) = src.as_socket_ipv6().map(|x| *x.ip())
                    else {
                        continue;
                    };
                    if let Ok(ra) = Icmp6RouterAdvertisement::from_wire(buf) {
                        self.handle_ra(ra, src);
                    }
                    if let Ok(rs) = Icmp6RouterSolicitation::from_wire(buf) {
                        self.handle_rs(&s, rs, src);
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        self.check_expired();
                        continue;
                    }
                    error!(self.log, "rx: {e}");
                }
            }
        }
    }

    /// Start the transmit loop, periodically sending out announcements.
    pub fn tx_loop(&self, sk: Socket, dropped: Arc<AtomicBool>) {
        const INTERVAL: Duration = Duration::from_secs(5);
        loop {
            if dropped.load(Ordering::SeqCst) {
                break;
            }
            send_ra(
                &sk,
                self.ifx.ip,
                None,
                self.ifx.index,
                self.router_lifetime,
                &self.log,
            );
            send_rs(&sk, self.ifx.ip, None, self.ifx.index, &self.log);
            sleep(INTERVAL);
        }
    }

    /// Handle a router advertisement. On reception the neighbor source address
    /// is updated as well as the time of reception and the stored advertisement
    /// containing the reachable time.
    fn handle_ra(&self, ra: Icmp6RouterAdvertisement, src: Ipv6Addr) {
        let mut guard = lock!(self.neighbor_router);
        let now = Instant::now();

        // Preserve first_seen from previous advertisement, or use now if this is the first
        let first_seen =
            guard.as_ref().map(|prev| prev.first_seen).unwrap_or(now);

        *guard = Some(ReceivedAdvertisement {
            first_seen,
            when: now,
            adv: ra,
            sender: src,
        });
    }

    /// Handle a router solicitation by sending an announcement to the
    /// sender.
    fn handle_rs(
        &self,
        sk: &Socket,
        // Don't really care what's in the solicitation for now, just
        // care that it parses as a valid RS.
        _rs: Icmp6RouterSolicitation,
        src: Ipv6Addr,
    ) {
        send_ra(
            sk,
            self.ifx.ip,
            Some(src),
            self.ifx.index,
            self.router_lifetime,
            &self.log,
        );
    }

    /// Check to see if the reachable time for our current peer (if any)
    /// is expired. If so, remove the peer.
    fn check_expired(&self) {
        let mut guard = lock!(self.neighbor_router);
        let Some(expired) = guard.as_ref().map(|nbr| nbr.expired()) else {
            return;
        };
        if expired {
            *guard = None;
        }
    }
}

/// Information about a network interface managed by the NDP manager.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6NetworkInterface {
    /// Interface's name
    pub name: String,
    /// Interface's address
    pub ip: Ipv6Addr,
    /// Interface's index
    pub index: u32,
}

/// Detailed information about a discovered peer on an interface.
#[derive(Debug, Clone)]
pub struct PeerAdvertisementInfo {
    /// The peer's IPv6 address
    pub address: Ipv6Addr,
    /// When the peer was first discovered
    pub first_seen: Instant,
    /// When the most recent Router Advertisement was received
    pub when: Instant,
    /// Router lifetime from the RA
    pub router_lifetime: u16,
    /// Reachable time from the RA
    pub reachable_time: u32,
    /// Retransmit timer from the RA
    pub retrans_timer: u32,
    /// Whether the peer has expired
    pub expired: bool,
}

/// Detailed information about an interface managed by NDP.
#[derive(Debug, Clone)]
pub struct InterfaceAdvertisementInfo {
    /// The interface details
    pub interface: Ipv6NetworkInterface,
    /// The router lifetime we advertise
    pub router_lifetime: u16,
    /// Discovered peer information (if any)
    pub discovered_peer: Option<PeerAdvertisementInfo>,
}
