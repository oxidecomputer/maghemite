// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest::peer::PeerId;
use std::fmt::{self, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{}", ip),
            Self::Interface(name) => write!(f, "{}", name),
        }
    }
}

impl From<IpAddr> for PeerId {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl From<&str> for PeerId {
    fn from(s: &str) -> Self {
        // Try to parse as IP first, otherwise treat as interface name
        if let Ok(ip) = s.parse::<IpAddr>() {
            Self::Ip(ip)
        } else {
            Self::Interface(s.to_string())
        }
    }
}

impl From<String> for PeerId {
    fn from(s: String) -> Self {
        // Try to parse as IP first, otherwise treat as interface name
        if let Ok(ip) = s.parse::<IpAddr>() {
            Self::Ip(ip)
        } else {
            Self::Interface(s)
        }
    }
}

impl From<Ipv4Addr> for PeerId {
    fn from(ip: Ipv4Addr) -> Self {
        Self::Ip(IpAddr::V4(ip))
    }
}

impl From<Ipv6Addr> for PeerId {
    fn from(ip: Ipv6Addr) -> Self {
        Self::Ip(IpAddr::V6(ip))
    }
}

impl FromStr for PeerId {
    type Err = std::convert::Infallible;

    /// Parse a PeerId from a string representation.
    /// Attempts to parse as an IP address first; if that fails, treats it as an interface name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(Self::Ip(ip))
        } else {
            Ok(Self::Interface(s.to_string()))
        }
    }
}

impl PeerId {
    /// Check if this represents an unnumbered peer
    pub fn is_unnumbered(&self) -> bool {
        matches!(self, Self::Interface(_))
    }

    /// Check if this represents a numbered peer
    pub fn is_numbered(&self) -> bool {
        matches!(self, Self::Ip(_))
    }
}
