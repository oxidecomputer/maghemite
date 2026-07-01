// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display and helper impls for the latest BGP neighbor / reset / config types.

use crate::latest;
use crate::latest::bgp::config::JitterRange;
use crate::latest::bgp::peer::PeerId;

impl Default for JitterRange {
    fn default() -> Self {
        Self { min: 0.75, max: 1.0 }
    }
}

impl std::str::FromStr for JitterRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 2 {
            return Err(
                "jitter range must be in format 'min,max' (e.g., '0.75,1.0')"
                    .to_string(),
            );
        }
        let min = parts[0].trim().parse::<f64>().map_err(|_| {
            format!("min value '{}' is not a valid float", parts[0].trim())
        })?;
        let max = parts[1].trim().parse::<f64>().map_err(|_| {
            format!("max value '{}' is not a valid float", parts[1].trim())
        })?;
        Ok(JitterRange { min, max })
    }
}

impl std::fmt::Display for latest::bgp::config::NeighborResetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "neighbor {} asn {} op {:?}",
            self.peer, self.asn, self.op
        )
    }
}

impl latest::bgp::config::NeighborSelector {
    /// Convert peer string to PeerId using FromStr implementation.
    /// Tries to parse as IP first, otherwise treats as interface name.
    pub fn to_peer_id(&self) -> PeerId {
        self.peer.parse().expect("PeerId::from_str never fails")
    }
}

impl latest::bgp::config::NeighborConfig {
    /// Validate that at least one address family is enabled, and that
    /// `src_addr` (if set) is consistent with the peer kind:
    ///  - numbered (`PeerId::Ip`): same IP version as the peer address;
    ///  - unnumbered (`PeerId::Interface`): must be IPv6 (link-local).
    pub fn validate_address_families(&self) -> Result<(), String> {
        if self.ipv4_unicast.is_none() && self.ipv6_unicast.is_none() {
            return Err("at least one address family must be enabled".into());
        }
        if let Some(src) = self.src_addr {
            match &self.peer {
                PeerId::Ip(ip) => {
                    if ip.is_ipv4() != src.is_ipv4() {
                        return Err(format!(
                            "src_addr ({src}) IP version does not match peer ({ip}) IP version"
                        ));
                    }
                }
                PeerId::Interface(_) => {
                    if src.is_ipv4() {
                        return Err(format!(
                            "src_addr ({src}) must be IPv6 for unnumbered neighbors"
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}
