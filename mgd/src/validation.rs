// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared validation functions for API request handlers.

use dropshot::HttpError;
use mg_common::IpNetExt;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

/// Validate that all IPv4 prefixes have host bits unset and are valid for RIB.
///
/// Returns an HTTP 400 Bad Request error if any prefix:
/// - Has host bits set
/// - Is a loopback address (127.0.0.0/8)
/// - Is a multicast address (224.0.0.0/4)
///
/// Provides helpful error messages indicating the correct normalized format.
pub fn validate_prefixes_v4(prefixes: &[Ipv4Net]) -> Result<(), HttpError> {
    for prefix in prefixes {
        if !prefix.is_network_address() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} has host bits set. Use normalized prefix (e.g., 10.0.0.0/24 instead of 10.0.0.5/24)",
                    prefix
                ),
            ));
        }
        if !prefix.valid_for_rib() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} is not valid for RIB (loopback or multicast address)",
                    prefix
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
pub fn validate_prefixes_v6(prefixes: &[Ipv6Net]) -> Result<(), HttpError> {
    for prefix in prefixes {
        if !prefix.is_network_address() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} has host bits set. Use normalized prefix (e.g., 2001:db8::/64 instead of 2001:db8::1/64)",
                    prefix
                ),
            ));
        }
        if !prefix.valid_for_rib() {
            return Err(HttpError::for_bad_request(
                Some("InvalidPrefix".to_string()),
                format!(
                    "Prefix {} is not valid for RIB (loopback, multicast, or link-local address)",
                    prefix
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
pub fn validate_prefixes(prefixes: &[IpNet]) -> Result<(), HttpError> {
    let (p4, p6) = prefixes.iter().copied().fold(
        (Vec::new(), Vec::new()),
        |(mut p4, mut p6), p| {
            match p {
                IpNet::V4(prefix4) => p4.push(prefix4),
                IpNet::V6(prefix6) => p6.push(prefix6),
            };
            (p4, p6)
        },
    );

    validate_prefixes_v4(&p4)?;
    validate_prefixes_v6(&p6)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_validate_prefixes_v4_accepts_normalized() {
        let prefixes = vec![
            Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Net::new_unchecked(Ipv4Addr::new(192, 168, 0, 0), 16),
        ];
        assert!(validate_prefixes_v4(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v4_rejects_unnormalized() {
        let prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 5), 24)];
        let result = validate_prefixes_v4(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("10.0.0.5/24"));
        assert!(err.external_message.contains("host bits set"));
    }

    #[test]
    fn test_validate_prefixes_v6_accepts_normalized() {
        let prefixes = vec![
            Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            ),
            Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
                48,
            ),
        ];
        assert!(validate_prefixes_v6(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_unnormalized() {
        let prefixes = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            64,
        )];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("2001:db8::1/64"));
        assert!(err.external_message.contains("host bits set"));
    }

    #[test]
    fn test_validate_prefixes_v4_empty_list() {
        let prefixes: Vec<Ipv4Net> = vec![];
        assert!(validate_prefixes_v4(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v6_empty_list() {
        let prefixes: Vec<Ipv6Net> = vec![];
        assert!(validate_prefixes_v6(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v4_rejects_loopback() {
        let prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(127, 0, 0, 0), 8)];
        let result = validate_prefixes_v4(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v4_rejects_multicast() {
        let prefixes =
            vec![Ipv4Net::new_unchecked(Ipv4Addr::new(224, 0, 0, 0), 4)];
        let result = validate_prefixes_v4(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_loopback() {
        let prefixes = vec![Ipv6Net::new_unchecked(Ipv6Addr::LOCALHOST, 128)];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_multicast() {
        let prefixes = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
            8,
        )];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_link_local() {
        let prefixes = vec![Ipv6Net::new_unchecked(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            10,
        )];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_empty_list() {
        let prefixes: Vec<IpNet> = vec![];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_mixed_accepts_normalized() {
        let prefixes = vec![
            IpNet::V4(Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24)),
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            IpNet::V4(Ipv4Net::new_unchecked(
                Ipv4Addr::new(192, 168, 0, 0),
                16,
            )),
        ];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_rejects_unnormalized_v4() {
        let prefixes = vec![
            IpNet::V4(Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24)),
            IpNet::V4(Ipv4Net::new_unchecked(
                Ipv4Addr::new(192, 168, 1, 5),
                24,
            )),
        ];
        let result = validate_prefixes(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("192.168.1.5/24"));
    }

    #[test]
    fn test_validate_prefixes_rejects_unnormalized_v6() {
        let prefixes = vec![
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
                64,
            )),
        ];
        let result = validate_prefixes(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("2001:db8:1::1/64"));
    }

    #[test]
    fn test_validate_prefixes_rejects_invalid_for_rib_v4() {
        let prefixes = vec![
            IpNet::V4(Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24)),
            IpNet::V4(Ipv4Net::new_unchecked(Ipv4Addr::new(127, 0, 0, 0), 8)),
        ];
        let result = validate_prefixes(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_rejects_invalid_for_rib_v6() {
        let prefixes = vec![
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            IpNet::V6(Ipv6Net::new_unchecked(Ipv6Addr::LOCALHOST, 128)),
        ];
        let result = validate_prefixes(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_only_v4() {
        let prefixes = vec![
            IpNet::V4(Ipv4Net::new_unchecked(Ipv4Addr::new(10, 0, 0, 0), 24)),
            IpNet::V4(Ipv4Net::new_unchecked(
                Ipv4Addr::new(192, 168, 0, 0),
                16,
            )),
        ];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_only_v6() {
        let prefixes = vec![
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            IpNet::V6(Ipv6Net::new_unchecked(
                Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
                48,
            )),
        ];
        assert!(validate_prefixes(&prefixes).is_ok());
    }
}
