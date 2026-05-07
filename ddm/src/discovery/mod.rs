// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This module implements the ddm router discovery mechanisms. These
//! mechanisms are responsible for three primary things
//!
//! 1. Soliciting other routers through UDP/IPv6 link local multicast.
//! 2. Sending out router advertisements in response to solicitations.
//! 3. Continuously soliciting link-local at a configurable rate to keep
//!    sessions alive and sending out notifications when peering arrangements
//!    expire due to not getting a solicitation response within a configurable
//!    time threshold.
//!
//! [`Version`] and [`DiscoveryError`] are platform-agnostic and stay in this
//! module so the state machine type definitions in [`crate::sm`] continue to
//! compile when the routing runtime is gated out (e.g. Linux test fixtures
//! running ddmd with `--no-state-machine`). The runtime helpers that drive
//! the protocol over UDPv6 sockets live in the [`runtime`] submodule and
//! are illumos-only.
//!
//! ## Protocol
//!
//! The general sequence of events is depicted in the following diagram.
//!
//!             *==========*                *==========*
//!             |  violin  |                |  piano   |
//!             *==========*                *==========*
//!                  |                           |
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |    advertise(fe80::47)    |
//!                  |<--------------------------|
//!                  |                           |
//!                  |            ...            |
//!                  |                           |
//!                  |                           |
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |    advertise(fe80::47)    |
//!                  |<--------------------------|
//!                  |                           |
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |     solicit(ff02::dd)     |
//!                  |-------------------------->|
//!                  |                           |
//!             +----|                           |
//!      expire |    |                           |
//!       piano |    |                           |
//!             +--->|                           |
//!
//! This shows violin sending a link-local multicast solicitation over the wire.
//! That solicitation is received by piano and piano respons with an
//! advertisement to violin's link-local unicast address. From this point
//! forward solicitations and responses continue. Each time violin gets a
//! response from piano, it updates the last seen timestamp for piano. If at
//! some point piano stops responding to solicitations and the last seen
//! timestamp is older than the expiration threshold, violin will expire the
//! session and send out a notification to the ddm state machine that started
//! it. Violin will continue to send out solicitations in case piano comes back.
//!
//! In the event that piano undergoes renumbering e.g. it's link-local unicast
//! address changes, this will be detected by violin and an advertisement update
//! will be sent to the ddm state machine through the notification channel
//! provided to the discovery subsystem.
//!
//! The DDM discovery multicast address is ff02::dd. Discovery packets are sent
//! over UDP using port number 0xddd.
//!
//! ## Packets
//!
//! Discovery packets follow a very simple format
//!
//!                      1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   version     |S A r r r r r r|  router kind  | hostname len  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           hostname                            :
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! :                             ....                              :
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! The first byte indicates the version. The only valid version at present is
//! version 1. The second byte is a flags bitfield. The first position `S`
//! indicates a solicitation. The second position `A` indicates and
//! advertisement. All other positions are reserved for future use. The third
//! byte indicates the kind of router. Current values are 0 for a server router
//! and 1 for a transit routers. The fourth byte is a hostname length followed
//! directly by a hostname of up to 255 bytes in length.

use thiserror::Error;

#[cfg(all(feature = "state-machine", target_os = "illumos"))]
mod runtime;

#[cfg(all(feature = "state-machine", target_os = "illumos"))]
pub(crate) use runtime::handler;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum Version {
    V2 = 2,
    V3 = 3,
}

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] ispf::Error),
}
