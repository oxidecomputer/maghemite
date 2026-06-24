// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::UnnumberedError;
use std::net::Ipv6Addr;

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

    fn get_active_interface_scope_id(
        &self,
        interface: &str,
    ) -> Result<Option<u32>, UnnumberedError>;

    fn get_discovered_ndp_neighbor(
        &self,
        interface: &str,
    ) -> Result<Option<Ipv6Addr>, UnnumberedError>;
}
