//! Neighbor discovery protocol support crate

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
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
    const MIN_PAYLOAD_LEN: usize = 16;

    pub fn from_wire(buf: &[u8]) -> Result<Self, Icmp6RaFromWireError> {
        // Per RFC 4861 Section 6.1.2: a valid RA has an ICMP payload of >= 16b
        if buf.len() < Self::MIN_PAYLOAD_LEN {
            return Err(Icmp6RaFromWireError::TooShort(buf.len()));
        }
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

    #[error("too short: {0} octets, expected at least 16")]
    TooShort(usize),

    #[error("wrong type: expected {expected}, got {0}", expected = Icmp6RouterAdvertisement::TYPE)]
    WrongType(u8),

    #[error("wrong code: expected {expected}, got {0}", expected = Icmp6RouterAdvertisement::CODE)]
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
    const MIN_PAYLOAD_LEN: usize = 8;
    // Source Link-Layer Address option.
    const OPTION_SLLA: u8 = 1;

    #[cfg(test)]
    pub(crate) fn from_wire(buf: &[u8]) -> Result<Self, Icmp6RsParseError> {
        Self::from_wire_impl(buf, None)
    }

    pub fn from_wire_with_source(
        buf: &[u8],
        source: Ipv6Addr,
    ) -> Result<Self, Icmp6RsParseError> {
        Self::from_wire_impl(buf, Some(source))
    }

    fn from_wire_impl(
        buf: &[u8],
        source: Option<Ipv6Addr>,
    ) -> Result<Self, Icmp6RsParseError> {
        // Per RFC 4861 Section 6.1.1: a valid RS has an ICMP payload of >= 8b.
        if buf.len() < Self::MIN_PAYLOAD_LEN {
            return Err(Icmp6RsParseError::TooShort(buf.len()));
        }

        let s: Self = ispf::from_bytes_be(buf)?;
        if s.typ != Self::TYPE {
            return Err(Icmp6RsParseError::WrongType(s.typ));
        }
        if s.code != Self::CODE {
            return Err(Icmp6RsParseError::WrongCode(s.code));
        }
        let has_slla = validate_nd_options(&buf[Self::MIN_PAYLOAD_LEN..])?;
        if let Some(source) = source {
            if source.is_multicast() {
                return Err(Icmp6RsParseError::MulticastSource(source));
            }
            if source.is_unspecified() && has_slla {
                return Err(Icmp6RsParseError::SllaFromUnspecifiedSource);
            }
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

fn validate_nd_options(buf: &[u8]) -> Result<bool, Icmp6RsOptionParseError> {
    let mut offset = 0;
    let mut has_slla = false;
    while offset < buf.len() {
        if buf.len() - offset < 2 {
            return Err(Icmp6RsOptionParseError::TruncatedHeader {
                remaining: buf.len() - offset,
            });
        }

        let option_type = buf[offset];
        let length = buf[offset + 1];
        if length == 0 {
            return Err(Icmp6RsOptionParseError::ZeroLength { option_type });
        }

        let option_len = usize::from(length) * 8;
        let next = offset + option_len;
        if next > buf.len() {
            return Err(Icmp6RsOptionParseError::TruncatedOption {
                option_type,
                option_len,
                remaining: buf.len() - offset,
            });
        }

        if option_type == Icmp6RouterSolicitation::OPTION_SLLA {
            has_slla = true;
        }
        offset = next;
    }

    Ok(has_slla)
}

#[derive(Debug, thiserror::Error)]
pub enum Icmp6RsParseError {
    #[error("deserialization error: {0}")]
    Ispf(#[from] ispf::Error),

    #[error("too short: {0} octets, expected at least 8")]
    TooShort(usize),

    #[error("invalid option: {0}")]
    Option(#[from] Icmp6RsOptionParseError),

    /// Source Link-Layer Address option is invalid from an unspecified source.
    #[error("SLLA option is invalid from unspecified source")]
    SllaFromUnspecifiedSource,

    #[error("multicast source address is invalid for router solicitation: {0}")]
    MulticastSource(Ipv6Addr),

    #[error("wrong type: expected {expected}, got {0}", expected = Icmp6RouterSolicitation::TYPE)]
    WrongType(u8),

    #[error("wrong code: expected {expected}, got {0}", expected = Icmp6RouterSolicitation::CODE)]
    WrongCode(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum Icmp6RsOptionParseError {
    #[error("truncated option header: {remaining} octets remaining")]
    TruncatedHeader { remaining: usize },

    #[error("option {option_type} has zero length")]
    ZeroLength { option_type: u8 },

    #[error(
        "option {option_type} length {option_len} exceeds {remaining} remaining octets"
    )]
    TruncatedOption {
        option_type: u8,
        option_len: usize,
        remaining: usize,
    },
}
