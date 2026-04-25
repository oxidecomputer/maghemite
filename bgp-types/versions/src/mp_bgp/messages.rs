// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BGP wire-message types added in the MP_BGP API version.

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
