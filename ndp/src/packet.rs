//! Neighbor discovery protocol support crate

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// ICMP6 router advertisement
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     Type      |     Code      |          Checksum             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Reachable Time                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          Retrans Timer                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Icmp6RouterAdvertisement {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub hop_limit: u8,
    pub flags: u8,
    pub lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
}

impl Icmp6RouterAdvertisement {
    const TYPE: u8 = 134;
    const CODE: u8 = 0;
    const DEFAULT_HOPLIMIT: u8 = 255;

    pub fn from_wire(buf: &[u8]) -> Result<Self, Icmp6RaFromWireError> {
        let s: Self = ispf::from_bytes_be(buf)?;
        if s.typ != Self::TYPE {
            return Err(Icmp6RaFromWireError::WrongType(s.typ));
        }
        if s.code != Self::CODE {
            return Err(Icmp6RaFromWireError::WrongCode(s.code));
        }
        Ok(s)
    }

    // While RFC 4861 says 0 means unspecified, it's not clear how to interpret
    // that from the perspective of a discovery engine. One interpretation may
    // be that the reachable time is forever, another may be that reachable time
    // is zero. Ten seconds is double our solicit interval, so if we get to a
    // place where we don't have RAs inside 10 seconds, something has gone
    // sideways.
    pub fn effective_reachable_time(&self) -> Duration {
        if self.reachable_time == 0 {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(self.reachable_time.into())
        }
    }
}

impl Default for Icmp6RouterAdvertisement {
    fn default() -> Self {
        Self {
            typ: Self::TYPE,
            code: Self::CODE,
            checksum: 0,
            hop_limit: Self::DEFAULT_HOPLIMIT,
            flags: 0,
            lifetime: 0, //indicates this is not a default router
            reachable_time: 0,
            retrans_timer: 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Icmp6RaFromWireError {
    #[error("deserialization error: {0}")]
    Ispf(#[from] ispf::Error),

    #[error("wrong type: expected {}, got {0}", Icmp6RouterAdvertisement::TYPE)]
    WrongType(u8),

    #[error("wrong code: expected {}, got {0}", Icmp6RouterAdvertisement::CODE)]
    WrongCode(u8),
}

/// ICMP6 router solicitation
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |     Code      |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Reserved                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub struct Icmp6RouterSolicitation {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub reserved: u32,
}

impl Icmp6RouterSolicitation {
    const TYPE: u8 = 133;
    const CODE: u8 = 0;

    pub fn from_wire(buf: &[u8]) -> Result<Self, Icmp6RsFromWireError> {
        let s: Self = ispf::from_bytes_be(buf)?;
        if s.typ != Self::TYPE {
            return Err(Icmp6RsFromWireError::WrongType(s.typ));
        }
        if s.code != Self::CODE {
            return Err(Icmp6RsFromWireError::WrongCode(s.code));
        }
        Ok(s)
    }
}

impl Default for Icmp6RouterSolicitation {
    fn default() -> Self {
        Self {
            typ: Self::TYPE,
            code: Self::CODE,
            checksum: 0,
            reserved: 0,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Icmp6RsFromWireError {
    #[error("deserialization error: {0}")]
    Ispf(#[from] ispf::Error),

    #[error("wrong type: expected {}, got {0}", Icmp6RouterSolicitation::TYPE)]
    WrongType(u8),

    #[error("wrong code: expected {}, got {0}", Icmp6RouterSolicitation::CODE)]
    WrongCode(u8),
}
