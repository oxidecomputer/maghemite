// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Parsing of Tofino port (`tfport`) datalink names.
//!
//! Tofino switch ports are surfaced to the host as illumos datalinks named
//! `tfport<kind><port>_<link>`; e.g., `tfportqsfp10_0` (front panel) or
//! `tfportrear0_0` (backplane). This module parses this datalink naming
//! convention into its specific components, allowing callers to easily map a
//! datalink name back to a switch port identifier.
//!
//! Note: VLAN links over an uplink append the VLAN ID after a `.`, e.g.,
//! `tfportqsfp0_0.100`, as surfaced by Dendrite's `uplinkd` ([VLAN naming]).
//!
//! [VLAN naming]: https://github.com/oxidecomputer/dendrite/blob/3019e6f0c73ded56be5c36cbaca82dbbc796a346/uplinkd/src/main.rs#L251-L256

use dpd_client::types;

/// Prefix shared by every `tfport` datalink name.
const TFPORT_DEVICE_PREFIX: &str = "tfport";

/// The switch-port device kind encoded into a `tfport` datalink name.
///
/// Front-panel links typically appear as `qsfp`. Backplane links to sleds
/// appear as `rear`, which are the only ports ddmd currently programs as
/// underlay multicast members for ingress multicast traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TfportKind {
    Qsfp,
    Rear,
}

impl TfportKind {
    /// The device token as it appears both in a tfport name (`tfportrear0_0`)
    /// and in a DPD port name (`rear0`).
    fn token(self) -> &'static str {
        match self {
            TfportKind::Qsfp => "qsfp",
            TfportKind::Rear => "rear",
        }
    }

    /// Parse a device kind from its datalink token (`qsfp`, `rear`).
    fn from_token(s: &str) -> Option<Self> {
        match s {
            "qsfp" => Some(TfportKind::Qsfp),
            "rear" => Some(TfportKind::Rear),
            _ => None,
        }
    }
}

/// Components parsed from a `tfport` datalink name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TfportName {
    /// Device kind (front-panel vs backplane).
    kind: TfportKind,
    /// Switch port number within the kind.
    port: u8,
    /// Link (lane) number within the port.
    link: u8,
    /// Optional VLAN tag appended after a `.`.
    vlan: Option<u16>,
}

/// Parse a `tfport` datalink name into its components.
///
/// # Errors
///
/// Returns an error if `name` lacks the specified `tfport` prefix, points to
/// an unrecognized device kind, or has malformed port/link/vlan fields.
fn parse_tfport_name(name: &str) -> Result<TfportName, String> {
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

    let (port_link, vlan) = rest
        .split_once('.')
        .map_or((rest, None), |(port_link, vlan)| (port_link, Some(vlan)));

    let (port, link) = port_link
        .split_once('_')
        .ok_or_else(|| format!("{name} has no link id"))?;

    let port = parse_number::<u8>(port)
        .ok_or_else(|| format!("{name} has invalid port {port}"))?;

    let link = parse_number::<u8>(link)
        .ok_or_else(|| format!("{name} has invalid link id {link}"))?;

    // A second `.` (e.g. `tfportqsfp10_0.100.200`) leaves a non-numeric
    // remainder, rejected by the parse op below.
    let vlan = vlan
        .map(|vlan| {
            parse_number::<u16>(vlan)
                .ok_or_else(|| format!("{name} has invalid vlan {vlan}"))
        })
        .transpose()?;

    Ok(TfportName {
        kind,
        port,
        link,
        vlan,
    })
}

/// Parse a port, link, or VLAN number made only of ASCII digits.
///
/// `str::parse` accepts a leading `+`, which no tfport name conveys,
/// so we have to rule out a sign or any other non-digit before parsing.
fn parse_number<T: std::str::FromStr>(s: &str) -> Option<T> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Build a DPD [`PortId`] from a parsed tfport kind and port number.
///
/// # Errors
///
/// Returns an error if the synthesized port name is not a valid DPD `qsfp` or
/// `rear` port identifier.
///
/// [`PortId`]: dpd_client::types::PortId
fn tfport_port_id(
    kind: TfportKind,
    port: u8,
) -> Result<dpd_client::types::PortId, String> {
    let port_name = format!("{}{port}", kind.token());
    match kind {
        TfportKind::Qsfp => types::Qsfp::try_from(port_name.as_str())
            .map(types::PortId::Qsfp)
            .map_err(|e| format!("bad qsfp port name {port_name}: {e}")),
        TfportKind::Rear => types::Rear::try_from(port_name.as_str())
            .map(types::PortId::Rear)
            .map_err(|e| format!("bad rear port name {port_name}: {e}")),
    }
}

/// Resolve a tfport datalink name (e.g. `tfportrear0_0`) to the DPD
/// ([`PortId`], [`LinkId`]) pair that names the switch port and link.
///
/// # Errors
///
/// Returns an error if `ifname` is not a valid tfport datalink name or its
/// kind and port do not form a valid DPD port identifier.
///
/// [`PortId`]: dpd_client::types::PortId
/// [`LinkId`]: dpd_client::types::LinkId
pub fn port_link_from_ifname(
    ifname: &str,
) -> Result<(dpd_client::types::PortId, dpd_client::types::LinkId), String> {
    port_link(&parse_tfport_name(ifname)?)
}

fn port_link(
    tfport: &TfportName,
) -> Result<(dpd_client::types::PortId, dpd_client::types::LinkId), String> {
    let port_id = tfport_port_id(tfport.kind, tfport.port)?;
    // Breakout lanes surface up as distinct datalinks (`tfportqsfp0_0`,
    // `tfportqsfp0_1`, ...), sharing one `PortId`. The parsed link is the
    // lane, which is the DPD `LinkId`.
    let link_id = dpd_client::types::LinkId(tfport.link);
    Ok((port_id, link_id))
}

/// Resolve an untagged tfport datalink name to its DPD `(PortId, LinkId)`.
///
/// Unlike [`port_link_from_ifname`], which ignores a VLAN suffix, this
/// method rejects it. A `(PortId, LinkId)` names the untagged port and link.
/// Resolving a VLAN interface to it would program state with the incorrect
/// tagging.
///
/// DDM peers operate over untagged links, using this naming convention, while
/// mg-lower keeps the more open convention for next hops on [VLAN uplinks].
///
/// # Errors
///
/// Returns an error if `ifname` carries a VLAN suffix, or for any reason
/// [`port_link_from_ifname`] would.
///
/// [VLAN uplinks]: https://github.com/oxidecomputer/dendrite/blob/3019e6f0c73ded56be5c36cbaca82dbbc796a346/uplinkd/src/main.rs#L251-L256
pub fn port_link_from_untagged_ifname(
    ifname: &str,
) -> Result<(dpd_client::types::PortId, dpd_client::types::LinkId), String> {
    let tfport = parse_tfport_name(ifname)?;
    if let Some(vlan) = tfport.vlan {
        return Err(format!(
            "{ifname} is a vlan {vlan} interface, expected an untagged tfport"
        ));
    }
    port_link(&tfport)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn name(
        kind: TfportKind,
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
        assert_eq!(
            parse_tfport_name("tfportqsfp10_0").unwrap(),
            name(TfportKind::Qsfp, 10, 0, None)
        );
        assert_eq!(
            parse_tfport_name("tfportqsfp10_0.100").unwrap(),
            name(TfportKind::Qsfp, 10, 0, Some(100))
        );
        assert_eq!(
            parse_tfport_name("tfportqsfp010_00.00100").unwrap(),
            name(TfportKind::Qsfp, 10, 0, Some(100))
        );
        assert_eq!(
            parse_tfport_name("tfportqsfp1_1").unwrap(),
            name(TfportKind::Qsfp, 1, 1, None)
        );

        assert_eq!(
            parse_tfport_name("tfportrear0_0").unwrap(),
            name(TfportKind::Rear, 0, 0, None)
        );
        assert_eq!(
            parse_tfport_name("tfportrear31_0.200").unwrap(),
            name(TfportKind::Rear, 31, 0, Some(200))
        );

        // Malformed names.
        assert!(parse_tfport_name("fportqsfp10_0").is_err());
        assert!(parse_tfport_name("10_0").is_err());
        assert!(parse_tfport_name("tfportqsfp10").is_err());
        assert!(parse_tfport_name("tfportqsfp_10").is_err());
        assert!(parse_tfport_name("tfportqsfp0_").is_err());
        assert!(parse_tfport_name("tfportqsfp10_10_10").is_err());
        assert!(parse_tfport_name("tfportqsfp10.100_0").is_err());
        assert!(parse_tfport_name("tfportqsfp10_0.").is_err());
        assert!(parse_tfport_name("tfportqsfp10_0.100.200").is_err());
        assert!(parse_tfport_name("tfportrear0_0/ll").is_err());
        assert!(parse_tfport_name("tfportrear0_0/v6").is_err());

        // Unsupported or missing device kind.
        assert!(parse_tfport_name("tfportfoo0_0").is_err());
        assert!(parse_tfport_name("tfport0_0").is_err());

        // Invalid numeric components.
        assert!(parse_tfport_name("tfportqsfp1X_0.100").is_err());
        assert!(parse_tfport_name("tfportqsfp10_X.100").is_err());
        assert!(parse_tfport_name("tfportqsfp10_0.X").is_err());
        assert!(parse_tfport_name("tfportqsfp+1_0").is_err());
        assert!(parse_tfport_name("tfportqsfp1_+0").is_err());
        assert!(parse_tfport_name("tfportqsfp1_0.+100").is_err());
        assert!(parse_tfport_name("tfportqsfp1_0.65536").is_err());
    }

    #[test]
    fn untagged_resolution_rejects_vlan() {
        assert!(port_link_from_untagged_ifname("tfportrear0_0").is_ok());
        assert!(port_link_from_untagged_ifname("tfportrear0_0.100").is_err());
        assert!(port_link_from_ifname("tfportqsfp0_0.100").is_ok());
    }

    #[test]
    fn port_and_link_boundaries() {
        assert!(port_link_from_untagged_ifname("tfportqsfp31_0").is_ok());
        assert!(port_link_from_untagged_ifname("tfportqsfp32_0").is_err());
        assert!(port_link_from_untagged_ifname("tfportrear31_0").is_ok());
        assert!(port_link_from_untagged_ifname("tfportrear32_0").is_err());
        assert!(parse_tfport_name("tfportqsfp255_0").is_ok());
        assert!(parse_tfport_name("tfportqsfp256_0").is_err());
        assert!(parse_tfport_name("tfportqsfp0_255").is_ok());
        assert!(parse_tfport_name("tfportqsfp0_256").is_err());
        assert!(parse_tfport_name("tfportint0_0").is_err());
    }

    fn near_miss_kind() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("qsfp".to_string()),
            Just("rear".to_string()),
            "[a-z]{0,4}",
        ]
    }

    fn near_miss_number() -> impl Strategy<Value = String> {
        prop_oneof![
            "[0-9]{1,4}",
            "\\+[0-9]{1,3}",
            Just(String::new()),
            "[0-9]{1,2}[a-z/]",
        ]
    }

    fn near_miss_suffix() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            "\\.[0-9]{1,6}",
            Just(".".to_string()),
            "\\.[0-9]{1,3}\\.[0-9]{0,3}",
            "\\.[+-][0-9]{1,3}",
            "\\.[\u{0660}-\u{0669}\u{FF10}-\u{FF19}]{1,3}",
            "/[a-z0-9]{0,3}",
        ]
    }

    proptest! {
        /// Property: a well-formed name round-trips through the parser.
        ///
        /// The parser is purely syntactic, exercising the full u8/u16 ranges.
        #[test]
        fn prop_roundtrip(
            is_rear in any::<bool>(),
            port in any::<u8>(),
            link in any::<u8>(),
            vlan in proptest::option::of(any::<u16>()),
        ) {
            let kind =
                if is_rear { TfportKind::Rear } else { TfportKind::Qsfp };
            let mut ifname = format!("tfport{}{port}_{link}", kind.token());
            if let Some(vlan) = vlan {
                ifname.push_str(&format!(".{vlan}"));
            }
            prop_assert_eq!(
                parse_tfport_name(&ifname).unwrap(),
                TfportName { kind, port, link, vlan },
            );
        }

        /// Property: a DPD `PortId` formatted into a tfport name resolves back
        /// to the same `(PortId, LinkId)`.
        #[test]
        fn prop_resolves_dpd_port_names(
            is_rear in any::<bool>(),
            port in 0u8..32,
            link in any::<u8>(),
        ) {
            let port_id = if is_rear {
                types::PortId::Rear(
                    types::Rear::try_from(format!("rear{port}").as_str())
                        .unwrap(),
                )
            } else {
                types::PortId::Qsfp(
                    types::Qsfp::try_from(format!("qsfp{port}").as_str())
                        .unwrap(),
                )
            };
            let ifname = format!("tfport{port_id}_{link}");
            prop_assert_eq!(
                port_link_from_untagged_ifname(&ifname).unwrap(),
                (port_id, types::LinkId(link)),
            );
        }

        /// Property: parsing arbitrary input never panics.
        #[test]
        fn prop_never_panics(ifname in ".*") {
            let _ = parse_tfport_name(&ifname);
        }

        /// Property: canonical formatting preserves the parsed components.
        #[test]
        fn prop_accepted_names_roundtrip(
            kind in near_miss_kind(),
            port in near_miss_number(),
            sep in prop_oneof![Just(""), Just("_"), Just("__")],
            link in near_miss_number(),
            suffix in near_miss_suffix(),
        ) {
            let ifname = format!("tfport{kind}{port}{sep}{link}{suffix}");
            if let Ok(name) = parse_tfport_name(&ifname) {
                let mut canonical = format!(
                    "tfport{}{}_{}",
                    name.kind.token(),
                    name.port,
                    name.link,
                );
                if let Some(vlan) = name.vlan {
                    canonical.push_str(&format!(".{vlan}"));
                }
                prop_assert_eq!(parse_tfport_name(&canonical), Ok(name));
            }
        }
    }
}
