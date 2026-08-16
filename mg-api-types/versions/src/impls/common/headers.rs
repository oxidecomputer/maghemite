// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt;
use std::str::FromStr;

use crate::latest::common::headers::Dscp;

impl Dscp {
    pub const CS0: Self = Self(0b000000); // 0
    pub const CS1: Self = Self(0b001000); // 8
    pub const CS2: Self = Self(0b010000); // 16
    pub const CS3: Self = Self(0b011000); // 24
    pub const CS4: Self = Self(0b100000); // 32
    pub const CS5: Self = Self(0b101000); // 40
    pub const CS6: Self = Self(0b110000); // 48
    pub const CS7: Self = Self(0b111000); // 56

    /// Create a new Dscp from a raw 6-bit value (0-63).
    pub fn from_dscp_value(val: u8) -> Result<Self, String> {
        Self::try_from(val)
    }

    /// Create a DSCP value from a TOS/Traffic-Class byte as
    /// returned by `getsockopt(IP_TOS)` or `getsockopt(IPV6_TCLASS)`.
    /// Extracts the upper 6 bits (DSCP), ignoring the lower 2 ECN
    /// bits.
    pub fn from_tos_byte(tos: u8) -> Self {
        Self(tos >> 2)
    }

    /// Return the raw numeric value (0-63).
    pub fn as_dscp_value(self) -> u8 {
        self.0
    }

    /// Return the TOS/Traffic-Class byte for use with `IP_TOS` or
    /// `IPV6_TCLASS`. The DSCP value occupies the upper 6 bits of
    /// the byte (value << 2), with the lower 2 ECN bits left zero.
    pub fn as_tos_byte(self) -> u8 {
        self.0 << 2
    }
}

impl Default for Dscp {
    fn default() -> Self {
        Self::CS0
    }
}

impl fmt::Display for Dscp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_dscp_value())
    }
}

impl FromStr for Dscp {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val: u8 =
            s.parse().map_err(|_| format!("invalid DSCP value: {s}"))?;
        Self::from_dscp_value(val)
    }
}
