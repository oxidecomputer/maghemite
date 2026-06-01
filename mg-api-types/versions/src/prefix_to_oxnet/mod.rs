// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `PREFIX_TO_OXNET` of the Maghemite Admin API.
//!
//! Replaces `Prefix4`/`Prefix6` with `oxnet::Ipv4Net`/`oxnet::Ipv6Net` in
//! BGP message types (`UpdateMessage`, `MpReachIpv4/6Unicast`,
//! `MpUnreachIpv4/6Unicast`) and the message-history response.

pub mod bgp;
