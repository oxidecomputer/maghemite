// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BGP wire-message types added in the MP_BGP API version.

use std::net::{Ipv4Addr, Ipv6Addr};

use num_enum::{IntoPrimitive, TryFromPrimitive};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Address families supported by Maghemite BGP.
#[derive(
    Debug,
    Copy,
    Clone,
    Deserialize,
    Eq,
    IntoPrimitive,
    JsonSchema,
    PartialEq,
    Serialize,
    TryFromPrimitive,
)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[repr(u16)]
pub enum Afi {
    /// Internet protocol version 4
    Ipv4 = 1,
    /// Internet protocol version 6
    Ipv6 = 2,
}

/// IPv6 double nexthop: global unicast address + link-local address.
/// Per RFC 2545, when advertising IPv6 routes, both addresses may be present.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct Ipv6DoubleNexthop {
    /// Global unicast address
    pub global: Ipv6Addr,
    /// Link-local address
    pub link_local: Ipv6Addr,
}

/// BGP next-hops can come in multiple forms, defined in several different RFCs.
/// This enum represents the forms supported by this implementation.
///
/// In the case of IPv6, RFC 2545 defined the use of either:
/// 1) A single non-link-local next-hop (length=16)
/// 2) A non-link-local plus a link-local next-hop (length=32)
///
/// This does not account for only a link-local address as the sole next-hop.
/// As such, many different implementations decided they would encode this in a
/// variety of ways (since there was no canonical source of truth):
/// a) Single-address encoding just the link-local (length=16)
/// b) Double-address encoding the link-local in both positions (length=32)
/// c) Double-address encoding the link-local in its normal position, but 0's in
///    the non-link-local position (length=32)
/// etc.
/// This led to `draft-ietf-idr-linklocal-capability` which specifies more
/// detailed encoding and error handling standards, signaled via a new
/// Link-Local Next Hop Capability.
///
/// In addition to this, RFC 8950 (formerly RFC 5549) specified the
/// advertisement of IPv4 NLRI via an IPv6 next-hop, enabled via the Extended
/// Next Hop capability.
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
#[schemars(
    description = "A BGP next-hop address in one of three formats: IPv4, IPv6 single, or IPv6 double."
)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Ipv6Single(Ipv6Addr),
    Ipv6Double(Ipv6DoubleNexthop),
}

/// Element of the RFC 8950 Extended Next Hop Encoding capability advertising a
/// supported (AFI, SAFI, NextHop AFI) tuple.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    JsonSchema,
    PartialOrd,
    Ord,
)]
pub struct ExtendedNexthopElement {
    pub afi: u16,
    pub safi: u16,
    pub nh_afi: u16,
}
