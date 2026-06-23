// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `MD5_AUTH_STRING` of the Maghemite Admin API.
//!
//! Replaces `Option<String>` with `Option<Md5AuthString>` which upholds
//! invariants about what values are acceptable as keys for the MD5 TCP option.
//! This mainly updates `BgpPeerParameters` but trickles down to all its
//! consumers.

pub mod bgp;
pub mod rdb;
