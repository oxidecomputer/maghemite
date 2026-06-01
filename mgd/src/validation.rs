// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared validation functions for API request handlers.

use dropshot::HttpError;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

pub trait RibValid {
    fn valid_for_rib(&self) -> bool;
}

impl RibValid for Ipv4Net {
    fn valid_for_rib(&self) -> bool {
        let addr = self.addr();
        !(addr.is_loopback()
            || addr.is_multicast()
            || addr.is_unspecified() && self.width() == 32)
    }
}

impl RibValid for Ipv6Net {
    fn valid_for_rib(&self) -> bool {
        let addr = self.addr();
        !(addr.is_loopback()
            || addr.is_multicast()
            || addr.is_unicast_link_local()
            || addr.is_unspecified() && self.width() == 128)
    }
}

impl RibValid for IpNet {
    fn valid_for_rib(&self) -> bool {
        match self {
            IpNet::V4(n) => n.valid_for_rib(),
            IpNet::V6(n) => n.valid_for_rib(),
        }
    }
}

/// Validate that all IPv4 prefixes have host bits unset and are valid for RIB.
///
/// Returns an HTTP 400 Bad Request error if any prefix:
/// - Has host bits set
/// - Is a loopback address (127.0.0.0/8)
/// - Is a multicast address (224.0.0.0/4)
///
/// Provides helpful error messages indicating the correct normalized format.
pub fn validate_ipv4_nets(nets: &[Ipv4Net]) -> Result<(), HttpError> {
    for net in nets {
        if !net.is_network_address() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} has host bits set. Use normalized prefix (e.g., 10.0.0.0/24 instead of 10.0.0.5/24)",
                    net
                ),
            ));
        }
        if !net.valid_for_rib() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} is not valid for RIB (loopback or multicast address)",
                    net
                ),
            ));
        }
    }
    Ok(())
}

/// Validate that all IPv6 prefixes have host bits unset and are valid for RIB.
///
/// Returns an HTTP 400 Bad Request error if any prefix:
/// - Has host bits set
/// - Is a loopback address (::1/128)
/// - Is a multicast address (ff00::/8)
/// - Is a link-local unicast address (fe80::/10)
///
/// Provides helpful error messages indicating the correct normalized format.
pub fn validate_ipv6_nets(nets: &[Ipv6Net]) -> Result<(), HttpError> {
    for net in nets {
        if !net.is_network_address() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} has host bits set. Use normalized prefix (e.g., 2001:db8::/64 instead of 2001:db8::1/64)",
                    net
                ),
            ));
        }
        if !net.valid_for_rib() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} is not valid for RIB (loopback, multicast, or link-local address)",
                    net
                ),
            ));
        }
    }
    Ok(())
}

/// Validate a mixed list of IPv4 and IPv6 prefixes.
///
/// This function separates the prefixes by address family and dispatches
/// to the appropriate validation function. All prefixes must have host bits
/// unset and be valid for RIB.
///
/// Returns an HTTP 400 Bad Request error if any prefix fails validation.
pub fn validate_nets(nets: &[IpNet]) -> Result<(), HttpError> {
    for net in nets {
        match net {
            IpNet::V4(n) => validate_ipv4_nets(std::slice::from_ref(n))?,
            IpNet::V6(n) => validate_ipv6_nets(std::slice::from_ref(n))?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_validate_ipv4_accepts_normalized() {
        let nets = vec![
            Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Net::new_unchecked(Ipv4Addr::new(192, 168, 0, 0), 16),
        ];
        assert!(validate_ipv4_nets(&nets).is_ok());
    }

    #[test]
    fn test_validate_ipv4_rejects_unnormalized() {
        let nets = vec![Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 5), 24)];
        let result = validate_ipv4_nets(&nets);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("host bits set"));
    }

    #[test]
    fn test_validate_ipv6_accepts_normalized() {
        let nets = vec![
            Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            ),
            Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
                48,
            ),
        ];
        assert!(validate_ipv6_nets(&nets).is_ok());
    }

    #[test]
    fn test_validate_ipv6_rejects_unnormalized() {
        let nets = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            64,
        )];
        let result = validate_ipv6_nets(&nets);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("host bits set"));
    }

    #[test]
    fn test_validate_ipv4_empty() {
        assert!(validate_ipv4_nets(&[]).is_ok());
    }

    #[test]
    fn test_validate_ipv6_empty() {
        assert!(validate_ipv6_nets(&[]).is_ok());
    }

    #[test]
    fn test_validate_ipv4_rejects_loopback() {
        let nets = vec![Ipv4Net::new_unchecked(Ipv4Addr::new(127, 0, 0, 0), 8)];
        let result = validate_ipv4_nets(&nets);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .external_message
                .contains("not valid for RIB")
        );
    }

    #[test]
    fn test_validate_ipv4_rejects_multicast() {
        let nets = vec![Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 4)];
        let result = validate_ipv4_nets(&nets);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .external_message
                .contains("not valid for RIB")
        );
    }

    #[test]
    fn test_validate_ipv6_rejects_loopback() {
        let nets = vec![Ipv6Net::new_unchecked(Ipv6Addr::LOCALHOST, 128)];
        let result = validate_ipv6_nets(&nets);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .external_message
                .contains("not valid for RIB")
        );
    }

    #[test]
    fn test_validate_ipv6_rejects_multicast() {
        let nets = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
            8,
        )];
        let result = validate_ipv6_nets(&nets);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .external_message
                .contains("not valid for RIB")
        );
    }

    #[test]
    fn test_validate_ipv6_rejects_link_local() {
        let nets = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            10,
        )];
        let result = validate_ipv6_nets(&nets);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .external_message
                .contains("not valid for RIB")
        );
    }

    #[test]
    fn test_validate_nets_empty() {
        assert!(validate_nets(&[]).is_ok());
    }

    #[test]
    fn test_validate_nets_mixed_accepts_normalized() {
        let nets = vec![
            IpNet::V4(Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24)),
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
        ];
        assert!(validate_nets(&nets).is_ok());
    }
}
