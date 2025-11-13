// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Shared validation functions for API request handlers.

use dropshot::HttpError;
use rdb::{Prefix, Prefix4, Prefix6};

/// Validate that all IPv4 prefixes have host bits unset and are valid for RIB.
///
/// Returns an HTTP 400 Bad Request error if any prefix:
/// - Has host bits set
/// - Is a loopback address (127.0.0.0/8)
/// - Is a multicast address (224.0.0.0/4)
///
/// Provides helpful error messages indicating the correct normalized format.
pub fn validate_prefixes_v4(prefixes: &[Prefix4]) -> Result<(), HttpError> {
    for prefix in prefixes {
        if !prefix.host_bits_are_unset() {
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
pub fn validate_prefixes_v6(prefixes: &[Prefix6]) -> Result<(), HttpError> {
    for prefix in prefixes {
        if !prefix.host_bits_are_unset() {
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
pub fn validate_prefixes(prefixes: &[Prefix]) -> Result<(), HttpError> {
    // Separate prefixes by address family
    let (p4, p6) = prefixes.iter().copied().fold(
        (Vec::new(), Vec::new()),
        |(mut p4, mut p6), p| {
            match p {
                Prefix::V4(prefix4) => p4.push(prefix4),
                Prefix::V6(prefix6) => p6.push(prefix6),
            };
            (p4, p6)
        },
    );

    // Validate each address family
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
            Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Prefix4::new(Ipv4Addr::new(192, 168, 0, 0), 16),
        ];
        assert!(validate_prefixes_v4(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v4_rejects_unnormalized() {
        let prefixes = vec![Prefix4 {
            value: Ipv4Addr::new(10, 0, 0, 5),
            length: 24,
        }];
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
            Prefix6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 64),
            Prefix6::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 48),
        ];
        assert!(validate_prefixes_v6(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_unnormalized() {
        let prefixes = vec![Prefix6 {
            value: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            length: 64,
        }];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("2001:db8::1/64"));
        assert!(err.external_message.contains("host bits set"));
    }

    #[test]
    fn test_validate_prefixes_v4_empty_list() {
        let prefixes: Vec<Prefix4> = vec![];
        assert!(validate_prefixes_v4(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v6_empty_list() {
        let prefixes: Vec<Prefix6> = vec![];
        assert!(validate_prefixes_v6(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_v4_rejects_loopback() {
        let prefixes = vec![Prefix4::new(Ipv4Addr::new(127, 0, 0, 0), 8)];
        let result = validate_prefixes_v4(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v4_rejects_multicast() {
        let prefixes = vec![Prefix4::new(Ipv4Addr::new(224, 0, 0, 0), 4)];
        let result = validate_prefixes_v4(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_loopback() {
        let prefixes = vec![Prefix6::new(Ipv6Addr::LOCALHOST, 128)];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_multicast() {
        let prefixes =
            vec![Prefix6::new(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8)];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_v6_rejects_link_local() {
        let prefixes =
            vec![Prefix6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10)];
        let result = validate_prefixes_v6(&prefixes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status_code, http::StatusCode::BAD_REQUEST);
        assert!(err.external_message.contains("not valid for RIB"));
    }

    #[test]
    fn test_validate_prefixes_empty_list() {
        let prefixes: Vec<Prefix> = vec![];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_mixed_accepts_normalized() {
        let prefixes = vec![
            Prefix::V4(Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            Prefix::V6(Prefix6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            Prefix::V4(Prefix4::new(Ipv4Addr::new(192, 168, 0, 0), 16)),
        ];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_rejects_unnormalized_v4() {
        let prefixes = vec![
            Prefix::V4(Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            Prefix::V4(Prefix4 {
                value: Ipv4Addr::new(192, 168, 1, 5),
                length: 24,
            }),
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
            Prefix::V6(Prefix6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            Prefix::V6(Prefix6 {
                value: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
                length: 64,
            }),
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
            Prefix::V4(Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            Prefix::V4(Prefix4::new(Ipv4Addr::new(127, 0, 0, 0), 8)),
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
            Prefix::V6(Prefix6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            Prefix::V6(Prefix6::new(Ipv6Addr::LOCALHOST, 128)),
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
            Prefix::V4(Prefix4::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            Prefix::V4(Prefix4::new(Ipv4Addr::new(192, 168, 0, 0), 16)),
        ];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    #[test]
    fn test_validate_prefixes_only_v6() {
        let prefixes = vec![
            Prefix::V6(Prefix6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                64,
            )),
            Prefix::V6(Prefix6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
                48,
            )),
        ];
        assert!(validate_prefixes(&prefixes).is_ok());
    }

    // Property-based tests to verify equivalence between generic and family-specific validators
    use proptest::prelude::*;

    // Strategy for generating any IPv4 prefix (normalized or unnormalized)
    fn any_ipv4_prefix_strategy() -> impl Strategy<Value = Prefix4> {
        (any::<u32>(), 0u8..=32u8).prop_map(|(addr_bits, length)| {
            // Don't use new() - we want to test both normalized and unnormalized
            Prefix4 {
                value: Ipv4Addr::from(addr_bits),
                length,
            }
        })
    }

    // Strategy for generating any IPv6 prefix (normalized or unnormalized)
    fn any_ipv6_prefix_strategy() -> impl Strategy<Value = Prefix6> {
        (any::<u128>(), 0u8..=128u8).prop_map(|(addr_bits, length)| {
            // Don't use new() - we want to test both normalized and unnormalized
            Prefix6 {
                value: Ipv6Addr::from(addr_bits),
                length,
            }
        })
    }

    // Helper function to compare validation results
    fn results_equivalent(
        r1: Result<(), HttpError>,
        r2: Result<(), HttpError>,
    ) -> bool {
        match (r1, r2) {
            (Ok(()), Ok(())) => true,
            (Err(e1), Err(e2)) => {
                // Both errors - compare status codes and error type
                e1.status_code == e2.status_code
                    && e1.error_code == e2.error_code
                    && e1.external_message.contains("host bits")
                        == e2.external_message.contains("host bits")
                    && e1.external_message.contains("not valid for RIB")
                        == e2.external_message.contains("not valid for RIB")
            }
            _ => false, // One Ok, one Err - not equivalent
        }
    }

    proptest! {
        /// Property: validate_prefixes with single Prefix::V4 is equivalent to validate_prefixes_v4
        #[test]
        fn prop_validate_prefixes_v4_equivalence(prefix4 in any_ipv4_prefix_strategy()) {
            let result_v4 = validate_prefixes_v4(&[prefix4]);
            let result_generic = validate_prefixes(&[Prefix::V4(prefix4)]);

            prop_assert!(
                results_equivalent(result_v4, result_generic),
                "validate_prefixes_v4 and validate_prefixes should give equivalent results"
            );
        }

        /// Property: validate_prefixes with single Prefix::V6 is equivalent to validate_prefixes_v6
        #[test]
        fn prop_validate_prefixes_v6_equivalence(prefix6 in any_ipv6_prefix_strategy()) {
            let result_v6 = validate_prefixes_v6(&[prefix6]);
            let result_generic = validate_prefixes(&[Prefix::V6(prefix6)]);

            prop_assert!(
                results_equivalent(result_v6, result_generic),
                "validate_prefixes_v6 and validate_prefixes should give equivalent results"
            );
        }

        /// Property: validate_prefixes with multiple V4 prefixes is equivalent to validate_prefixes_v4
        #[test]
        fn prop_validate_prefixes_v4_list_equivalence(
            prefixes in prop::collection::vec(any_ipv4_prefix_strategy(), 0..10)
        ) {
            let result_v4 = validate_prefixes_v4(&prefixes);
            let wrapped: Vec<Prefix> = prefixes.iter().map(|p| Prefix::V4(*p)).collect();
            let result_generic = validate_prefixes(&wrapped);

            prop_assert!(
                results_equivalent(result_v4, result_generic),
                "validate_prefixes_v4 and validate_prefixes should give equivalent results for lists"
            );
        }

        /// Property: validate_prefixes with multiple V6 prefixes is equivalent to validate_prefixes_v6
        #[test]
        fn prop_validate_prefixes_v6_list_equivalence(
            prefixes in prop::collection::vec(any_ipv6_prefix_strategy(), 0..10)
        ) {
            let result_v6 = validate_prefixes_v6(&prefixes);
            let wrapped: Vec<Prefix> = prefixes.iter().map(|p| Prefix::V6(*p)).collect();
            let result_generic = validate_prefixes(&wrapped);

            prop_assert!(
                results_equivalent(result_v6, result_generic),
                "validate_prefixes_v6 and validate_prefixes should give equivalent results for lists"
            );
        }
    }
}
