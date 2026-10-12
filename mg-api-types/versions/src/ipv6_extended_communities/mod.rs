// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `IPV6_EXTENDED_COMMUNITIES` of the Maghemite Admin API.
//!
//! Establishes a new path-attribute and message-history version boundary
//! for IPv6 Address Specific Extended Communities (RFC 5701). The shapes
//! initially preserve v12 behavior; community variants and wire support
//! can be added without changing historical API types.

pub mod bgp;
