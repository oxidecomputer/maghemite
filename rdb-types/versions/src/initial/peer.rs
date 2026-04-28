// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Identifies a BGP peer for session management and route tracking.
///
/// BGP peers can be identified in two ways:
/// - **Numbered**: Traditional BGP peering using explicit IP addresses
/// - **Unnumbered**: Modern peering using interface names with link-local addresses
///
/// # Unnumbered Peering
///
/// Unnumbered BGP uses interface names as stable identifiers instead of IP addresses.
/// This is important because:
/// - Link-local IPv6 addresses are discovered dynamically via NDP
/// - Multiple interfaces may have peers with the same link-local address
///   (e.g., fe80::1 on eth0 and fe80::1 on eth1)
/// - Scope ID (interface index) disambiguates link-local addresses, but is not
///   stable across reboots
/// - Interface names provide stable, unambiguous peer identification
///
/// # Route Tracking
///
/// This type is used in [`BgpPathProperties`](crate::BgpPathProperties) to track
/// which peer advertised a route. Using `PeerId` instead of `IpAddr` ensures:
/// - Unnumbered peers are properly distinguished even if they share link-local IPs
/// - Route cleanup correctly removes only the routes from the intended peer
/// - No cross-contamination when multiple unnumbered sessions exist
///
/// # Examples
///
/// ```
/// use rdb_types::PeerId;
/// use std::net::IpAddr;
///
/// // Numbered peer
/// let numbered = PeerId::Ip("192.0.2.1".parse::<IpAddr>().unwrap());
///
/// // Unnumbered peer
/// let unnumbered = PeerId::Interface("eth0".to_string());
/// ```
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum PeerId {
    /// Numbered peer identified by IP address
    ///
    /// Used for traditional BGP sessions where peers are configured with
    /// explicit IP addresses (either IPv4 or IPv6 global unicast).
    Ip(IpAddr),

    /// Unnumbered peer identified by interface name
    ///
    /// Used for unnumbered BGP sessions where peers are discovered via NDP
    /// on a specific interface. The interface name (e.g., "eth0") provides
    /// stable identification even though the peer's link-local address may
    /// be dynamic or shared with other interfaces.
    Interface(String),
}
