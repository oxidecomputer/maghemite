// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix4 {
    pub value: Ipv4Addr,
    pub length: u8,
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq, JsonSchema,
)]
pub struct Prefix6 {
    pub value: Ipv6Addr,
    pub length: u8,
}

#[derive(
    Debug,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    JsonSchema,
    PartialOrd,
    Ord,
)]
pub enum Prefix {
    V4(Prefix4),
    V6(Prefix6),
}
