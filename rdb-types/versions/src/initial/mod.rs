// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "clap")]
use clap::ValueEnum;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub mod peer;
pub mod prefix;

/// Represents the address family (protocol version) for network routes.
///
/// This is the canonical source of truth for address family definitions across the
/// entire codebase. All routing-related components (RIB operations, BGP messages,
/// API filtering, CLI tools) use this single enum rather than defining their own.
///
/// # Semantics
///
/// When used in filtering contexts (e.g., database queries or API parameters),
/// `Option<AddressFamily>` is preferred:
/// - `None` = no filter (match all address families)
/// - `Some(Ipv4)` = IPv4 routes only
/// - `Some(Ipv6)` = IPv6 routes only
///
/// # Examples
///
/// ```
/// use rdb_types::AddressFamily;
///
/// let ipv4 = AddressFamily::Ipv4;
/// let ipv6 = AddressFamily::Ipv6;
///
/// // For filtering, use Option
/// let filter: Option<AddressFamily> = Some(AddressFamily::Ipv4);
/// let no_filter: Option<AddressFamily> = None; // matches all families
/// ```
#[derive(
    Clone,
    Copy,
    Eq,
    Debug,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[cfg_attr(feature = "clap", derive(ValueEnum))]
pub enum AddressFamily {
    /// Internet Protocol Version 4 (IPv4)
    Ipv4,
    /// Internet Protocol Version 6 (IPv6)
    Ipv6,
}

#[derive(
    Debug,
    Copy,
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
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ProtocolFilter {
    /// BGP routes only
    Bgp,
    /// Static routes only
    Static,
}
