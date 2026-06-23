// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::UnnumberedError;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

/// NDP neighbor information returned by the unnumbered manager.
///
/// Contains the discovered peer's link-local IPv6 address and the interface
/// index (scope_id) needed to construct a properly scoped socket address.
/// The port is intentionally not included - the caller supplies the port per
/// the configuration for the BGP neighbor.
#[derive(Debug, Clone, Copy)]
pub struct NdpNeighbor {
    pub addr: Ipv6Addr,
    pub scope_id: u32,
}

impl NdpNeighbor {
    /// Convert to a SocketAddr with the specified port.
    pub fn to_socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(self.addr, port, 0, self.scope_id))
    }
}

/// Trait for managing unnumbered BGP sessions via NDP neighbor discovery.
///
/// This trait provides the interface between BGP and the external NDP/neighbor
/// discovery system, enabling:
/// - Dispatcher to route incoming link-local connections to the correct session
/// - SessionRunner to query for discovered peer addresses on unnumbered interfaces
///
/// This exists as a trait so UnnumberedManager can be completely stubbed out in
/// BGP tests that ensure invariants in the BGP FSM for unnumbered peers.
pub trait BgpUnnumbered: Send + Sync {
    fn get_active_interface_by_scope(
        &self,
        scope_id: u32,
    ) -> Result<Option<String>, UnnumberedError>;

    fn get_discovered_ndp_neighbor(
        &self,
        interface: &str,
    ) -> Result<Option<NdpNeighbor>, UnnumberedError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndp_neighbor_socket_addr_preserves_port_and_scope() {
        let neighbor = NdpNeighbor {
            addr: "fe80::1".parse().unwrap(),
            scope_id: 7,
        };

        let socket = neighbor.to_socket_addr(179);

        match socket {
            SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), neighbor.addr);
                assert_eq!(v6.port(), 179);
                assert_eq!(v6.flowinfo(), 0);
                assert_eq!(v6.scope_id(), 7);
            }
            SocketAddr::V4(_) => panic!("neighbor must produce IPv6 socket"),
        }
    }
}
