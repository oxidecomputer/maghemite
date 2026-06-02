// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Parsing of Tofino port (`tfport`) datalink names.
//!
//! Tofino switch ports are surfaced to the host as illumos datalinks named
//! `tfport<kind><port>_<link>[.vlan]`; for example, `tfportqsfp10_0` (front
//! panel) or `tfportrear0_0.100` (backplane). This module parses that form
//! into its components so callers can map a datalink name back to a switch
//! port without each one hand-rolling its own string handling.

/// Prefix shared by every `tfport` datalink name.
const TFPORT_DEVICE_PREFIX: &str = "tfport";

/// Switch-port device kind encoded in a `tfport` datalink name.
///
/// Front-panel links typically appear as `qsfp`. Backplane links toward other
/// sleds (the multicast underlay path) typically appear as `rear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TfportKind {
    Qsfp,
    Rear,
}

impl TfportKind {
    /// Device token as it appears both in a tfport name (`tfportrear0_0`) and
    /// in a dpd port name (`rear0`).
    pub fn token(self) -> &'static str {
        match self {
            TfportKind::Qsfp => "qsfp",
            TfportKind::Rear => "rear",
        }
    }

    /// Parse a device kind from its datalink token (`qsfp`, `rear`).
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "qsfp" => Some(TfportKind::Qsfp),
            "rear" => Some(TfportKind::Rear),
            _ => None,
        }
    }
}

/// Components parsed from a `tfport` datalink name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TfportName {
    /// Device kind (front-panel vs backplane).
    pub kind: TfportKind,
    /// Switch port number within the kind.
    pub port: u8,
    /// Link (lane) number within the port.
    pub link: u8,
    /// Optional VLAN tag appended after a `.`.
    pub vlan: Option<u16>,
}

/// Parse a `tfport` datalink name into its components.
///
/// # Examples
///
/// ```
/// use mg_common::tfport::{parse_tfport_name, TfportKind, TfportName};
/// assert_eq!(
///     parse_tfport_name("tfportqsfp10_0.100").unwrap(),
///     TfportName { kind: TfportKind::Qsfp, port: 10, link: 0, vlan: Some(100) },
/// );
/// assert_eq!(
///     parse_tfport_name("tfportrear0_0").unwrap(),
///     TfportName { kind: TfportKind::Rear, port: 0, link: 0, vlan: None },
/// );
/// ```
///
/// # Errors
///
/// Returns a human-readable message if `name` lacks the `tfport` prefix, has
/// an unrecognized device kind, or has malformed port/link/vlan fields.
pub fn parse_tfport_name(name: &str) -> Result<TfportName, String> {
    let body = name.strip_prefix(TFPORT_DEVICE_PREFIX).ok_or_else(|| {
        format!("{name} missing expected prefix {TFPORT_DEVICE_PREFIX}")
    })?;

    // The device kind is the leading alphabetic run (`qsfp`, `rear`), the
    // remainder carries the port/link/vlan numbers.
    let split = body
        .find(|c: char| !c.is_ascii_alphabetic())
        .ok_or_else(|| format!("{name} has no port id"))?;
    let (kind_str, rest) = body.split_at(split);
    let kind = TfportKind::from_token(kind_str).ok_or_else(|| {
        format!("{name} has unsupported device kind {kind_str}")
    })?;

    let (port_link, vlan_str) = match rest.split_once('.') {
        Some((port_link, vlan)) => (port_link, Some(vlan)),
        None => (rest, None),
    };

    let (port, link) = port_link
        .split_once('_')
        .ok_or_else(|| format!("{name} has no link id"))?;

    let port = port
        .parse::<u8>()
        .map_err(|_| format!("{name} has invalid port {port}"))?;

    let link = link
        .parse::<u8>()
        .map_err(|_| format!("{name} has invalid link id {link}"))?;

    let vlan = match vlan_str {
        None => None,
        // A second `.` (e.g. `tfportqsfp10_0.100.200`) leaves a non-numeric
        // remainder, so the parse below rejects it.
        Some(vlan) => Some(
            vlan.parse::<u16>()
                .map_err(|_| format!("{name} has invalid vlan {vlan}"))?,
        ),
    };

    Ok(TfportName {
        kind,
        port,
        link,
        vlan,
    })
}

/// Build a dpd [`PortId`] from a parsed tfport kind and port number.
///
/// # Errors
///
/// Returns a human-readable message if the synthesized port name is not a valid
/// dpd `qsfp` or `rear` port identifier.
///
/// [`PortId`]: dpd_client::types::PortId
pub fn tfport_port_id(
    kind: TfportKind,
    port: u8,
) -> Result<dpd_client::types::PortId, String> {
    use dpd_client::types;

    let port_name = format!("{}{}", kind.token(), port);
    match kind {
        TfportKind::Qsfp => types::Qsfp::try_from(&port_name)
            .map(types::PortId::Qsfp)
            .map_err(|e| format!("bad qsfp port name {port_name}: {e}")),
        TfportKind::Rear => types::Rear::try_from(&port_name)
            .map(types::PortId::Rear)
            .map_err(|e| format!("bad rear port name {port_name}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::TfportKind::{Qsfp, Rear};
    use super::{TfportName, parse_tfport_name};
    use proptest::prelude::*;

    fn name(
        kind: super::TfportKind,
        port: u8,
        link: u8,
        vlan: Option<u16>,
    ) -> TfportName {
        TfportName {
            kind,
            port,
            link,
            vlan,
        }
    }

    #[test]
    fn test_tfport_parser() {
        // Valid qsfp (front-panel) names.
        assert_eq!(
            parse_tfport_name("tfportqsfp10_0").unwrap(),
            name(Qsfp, 10, 0, None)
        );
        assert_eq!(
            parse_tfport_name("tfportqsfp10_0.100").unwrap(),
            name(Qsfp, 10, 0, Some(100))
        );
        assert_eq!(
            parse_tfport_name("tfportqsfp1_1").unwrap(),
            name(Qsfp, 1, 1, None)
        );

        // Valid rear (backplane) names.
        assert_eq!(
            parse_tfport_name("tfportrear0_0").unwrap(),
            name(Rear, 0, 0, None)
        );
        assert_eq!(
            parse_tfport_name("tfportrear31_0.200").unwrap(),
            name(Rear, 31, 0, Some(200))
        );

        // Malformed names.
        assert!(parse_tfport_name("fportqsfp10_0").is_err());
        assert!(parse_tfport_name("10_0").is_err());
        assert!(parse_tfport_name("tfportqsfp10").is_err());
        assert!(parse_tfport_name("tfportqsfp_10").is_err());
        assert!(parse_tfport_name("tfportqsfp0_").is_err());
        assert!(parse_tfport_name("tfportqsfp10_10_10").is_err());
        assert!(parse_tfport_name("tfportqsfp10.100_0").is_err());

        // Unsupported or missing device kind.
        assert!(parse_tfport_name("tfportfoo0_0").is_err());
        assert!(parse_tfport_name("tfport0_0").is_err());

        // Invalid numeric components.
        assert!(parse_tfport_name("tfportqsfp1X_0.100").is_err());
        assert!(parse_tfport_name("tfportqsfp10_X.100").is_err());
        assert!(parse_tfport_name("tfportqsfp10_0.X").is_err());
    }

    proptest! {
        /// Any well-formed name round-trips: formatting a kind, port, link,
        /// vlan tuple and parsing it back yields the same components. The
        /// parser is purely syntactic, so the full u8/u16 ranges are exercised.
        #[test]
        fn prop_roundtrip(
            is_rear in any::<bool>(),
            port in any::<u8>(),
            link in any::<u8>(),
            vlan in proptest::option::of(any::<u16>()),
        ) {
            let kind = if is_rear { Rear } else { Qsfp };
            let mut ifname = format!("tfport{}{port}_{link}", kind.token());
            if let Some(vlan) = vlan {
                ifname.push_str(&format!(".{vlan}"));
            }
            prop_assert_eq!(
                parse_tfport_name(&ifname).unwrap(),
                TfportName { kind, port, link, vlan },
            );
        }

        /// Parsing arbitrary input never panics; it always returns a `Result`.
        #[test]
        fn prop_never_panics(ifname in ".*") {
            let _ = parse_tfport_name(&ifname);
        }
    }
}
