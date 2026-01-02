// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::packet::{Icmp6RouterAdvertisement, Icmp6RouterSolicitation};
use crate::util::{
    ALL_NODES_MCAST, ListeningSocketError, ReceivedAdvertisement, send_ra,
};
use oxnet::Ipv6Net;
use slog::{Logger, error};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{sleep, spawn};
use std::time::{Duration, Instant};

const RA_INTERVAL: Duration = Duration::from_secs(5);

/// The `NdpManager` performs router discovery for a provided set of interfaces.
///
/// Use `add_interface` and `remove_interface` to manage discovery interfaces and
/// use `get_peer` to determine if a router peer has been discovered for a given
/// interface.
#[derive(Debug)]
pub struct NdpManager {
    /// Individual interface-level NDP managers.
    interfaces: RwLock<Vec<InterfaceNdpManager>>,
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
    pub fn add_interface(&self, ifx: Ipv6NetworkInterface) {
        self.interfaces
            .write()
            .unwrap()
            .push(InterfaceNdpManager::new(ifx, self.log.clone()))
    }

    /// Remove an interface from the NDP manager. Discovery is stopped when
    /// the interface is removed.
    pub fn remove_interface(&self, ifx: Ipv6NetworkInterface) -> bool {
        let mut ifxs_guard = self.interfaces.write().unwrap();
        let Some(pos) = ifxs_guard.iter().position(|x| x.ifx == ifx) else {
            return false;
        };

        ifxs_guard.remove(pos);
        true
    }

    /// Get a router peer, if any, that has been discovered for the given interface.
    pub fn get_peer(&self, ifx: &Ipv6NetworkInterface) -> Option<Ipv6Addr> {
        let ifxs_guard = self.interfaces.read().unwrap();
        let interface = ifxs_guard.iter().find(|x| &x.ifx == ifx)?;
        let nbr_guard = interface.neighbor_router.lock().unwrap();
        let neighbor_router = nbr_guard.as_ref()?;

        if neighbor_router.expired() {
            None
        } else {
            Some(neighbor_router.sender)
        }
    }
}

/// The `InterfaceNdpManager` runs router discovery for an individual interface.
///
/// Discovery is started on construction an dstopped when the interface manager
/// object is dropped.
#[derive(Debug, Clone)]
pub struct InterfaceNdpManager {
    ifx: Ipv6NetworkInterface,
    neighbor_router: Arc<Mutex<Option<ReceivedAdvertisement>>>,
    stop: Arc<AtomicBool>,
    log: Logger,
}

impl InterfaceNdpManager {
    /// Create a new interface manager for a given interface.
    pub fn new(ifx: Ipv6NetworkInterface, log: Logger) -> Self {
        let mgr = Self {
            ifx,
            neighbor_router: Arc::new(Mutex::new(None)),
            stop: Arc::new(AtomicBool::new(false)),
            log,
        };

        let s = mgr.clone();
        spawn(move || s.tx_loop());

        let s = mgr.clone();
        spawn(move || s.rx_loop());

        mgr
    }

    /// Run the interface NDP manager receive loop. Advertisements are used to
    /// set the current peer address. Advertisements are sent in response to
    /// solicitations.
    ///
    /// A read timeout of 1 second is used. When the time out hits instead of
    /// receiving a advertisement or solicitation packet, the current neighbor
    /// (if any) is checked for expiration.
    pub fn rx_loop(&self) {
        const BACKOFF_INTERVAL: Duration = Duration::from_secs(1);

        'outer: loop {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let s = match self.listening_socket() {
                Ok(s) => s,
                Err(e) => {
                    error!(self.log, "rx_loop: new multicast socket: {e}");
                    sleep(BACKOFF_INTERVAL);
                    continue;
                }
            };
            loop {
                if self.stop.load(Ordering::SeqCst) {
                    break 'outer;
                }
                let mut buf: [MaybeUninit<u8>; 1024] =
                    unsafe { MaybeUninit::uninit().assume_init() };

                match s.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        let buf: &[u8] = unsafe {
                            std::slice::from_raw_parts(buf.as_ptr().cast(), len)
                        };
                        let Some(src) = src.as_socket_ipv6().map(|x| *x.ip())
                        else {
                            continue;
                        };
                        if let Ok(ra) = Icmp6RouterAdvertisement::from_wire(buf)
                        {
                            self.handle_ra(ra, src);
                            continue;
                        }
                        if let Ok(rs) = Icmp6RouterSolicitation::from_wire(buf)
                        {
                            self.handle_rs(rs, src);
                            continue;
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            self.check_expired();
                            continue;
                        }
                        error!(self.log, "rx: {e}");
                        continue;
                    }
                }
            }
        }
    }

    /// Start the transmit loop, periodically sending out announcements every
    /// five seconds.
    pub fn tx_loop(&self) {
        loop {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            send_ra(self.ifx.ip.addr(), None, self.ifx.index, &self.log);
            sleep(RA_INTERVAL);
        }
    }

    /// Handle a router advertisement. On reception the neighbor source address
    /// is updated as well as the time of reception and the stored advertisement
    /// containing the reachable time.
    fn handle_ra(&self, ra: Icmp6RouterAdvertisement, src: Ipv6Addr) {
        let mut guard = self.neighbor_router.lock().unwrap();
        let nbr = &mut *guard;
        *nbr = Some(ReceivedAdvertisement {
            when: Instant::now(),
            adv: ra,
            sender: src,
        });
    }

    /// Handle a router solicitation by sending an announcement to the
    /// sender.
    fn handle_rs(&self, _rs: Icmp6RouterSolicitation, src: Ipv6Addr) {
        send_ra(self.ifx.ip.addr(), Some(src), self.ifx.index, &self.log);
    }

    /// Check to see if the reachable time for our current peer (if any)
    /// is expired. If so, remove the peer.
    fn check_expired(&self) {
        let mut guard = self.neighbor_router.lock().unwrap();
        let Some(expired) = guard.as_ref().map(|nbr| nbr.expired()) else {
            return;
        };
        if expired {
            *guard = None;
        }
    }

    /// Create a listening socket for solicitations and advertisements. This
    /// socket listens on the unspecified address to pick up both unicast
    /// and multicast solicitations and advertisements.
    fn listening_socket(&self) -> Result<Socket, ListeningSocketError> {
        use ListeningSocketError as E;
        const READ_TIMEOUT: Duration = Duration::from_secs(1);

        let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
            .map_err(E::NewSocketError)?;

        let sa = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, self.ifx.index)
            .into();

        s.set_reuse_address(true).map_err(E::ReuseAddress)?;

        s.set_multicast_if_v6(self.ifx.index)
            .map_err(E::SetMulticastIf)?;

        s.set_multicast_loop_v6(false)
            .map_err(E::SetMulticastLoop)?;

        s.join_multicast_v6(&ALL_NODES_MCAST, self.ifx.index)
            .map_err(E::JoinAllNodesMulticast)?;

        s.bind(&sa).map_err(ListeningSocketError::Bind)?;

        s.set_read_timeout(Some(READ_TIMEOUT))
            .map_err(E::SetReadTimeoutError)?;

        Ok(s)
    }
}

/// When an `InterfaceNdpManager` is dropped, the tx and rx loops are stopped.
impl Drop for InterfaceNdpManager {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Information about a network interface managed by the NDP manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6NetworkInterface {
    /// Interface's name
    pub name: String,
    /// Interface's address
    pub ip: Ipv6Net,
    /// Interface's index
    pub index: u32,
}
