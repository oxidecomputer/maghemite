// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Protocol types for DDM.

use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::HashSet;

pub mod v2;
pub mod v3;

// DDMv2 tunnel routes carry no path, so converting them to DDMv3 needs the
// peer they were received from. They are treated as originated by that peer.

impl v3::Update {
    /// Convert an update received from the DDMv2 peer `peer`.
    pub fn from_v2(value: v2::Update, peer: &str) -> Self {
        Self {
            tunnel: value.tunnel.map(|t| v3::TunnelUpdate::from_v2(t, peer)),
            underlay: value.underlay.map(v3::UnderlayUpdate::from),
        }
    }
}

impl From<v3::Update> for v2::Update {
    fn from(value: v3::Update) -> Self {
        Self {
            tunnel: value.tunnel.map(v2::TunnelUpdate::from),
            underlay: value.underlay.map(v2::UnderlayUpdate::from),
        }
    }
}

impl v3::PullResponse {
    /// Convert a pull response received from the DDMv2 peer `peer`.
    pub fn from_v2(value: v2::PullResponse, peer: &str) -> Self {
        // compilation barrier. if fields ever change, this destructure fails.
        let v2::PullResponse { underlay, tunnel } = value;

        Self {
            underlay: underlay
                .map(|x| x.into_iter().map(v3::PathVector::from).collect()),
            tunnel: tunnel.map(|x| {
                x.into_iter()
                    .map(|t| v3::TunnelOrigin::from_v2(t, peer))
                    .collect()
            }),
        }
    }
}

impl From<v3::PullResponse> for v2::PullResponse {
    fn from(value: v3::PullResponse) -> Self {
        // compilation barrier. if fields ever change, this destructure fails.
        let v3::PullResponse { underlay, tunnel } = value;

        Self {
            underlay: underlay
                .map(|x| x.into_iter().map(v2::PathVector::from).collect()),
            tunnel: tunnel
                .map(|x| x.into_iter().map(v2::TunnelOrigin::from).collect()),
        }
    }
}

impl From<v3::UnderlayUpdate> for v2::UnderlayUpdate {
    fn from(value: v3::UnderlayUpdate) -> Self {
        Self {
            announce: value
                .announce
                .into_iter()
                .map(v2::PathVector::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(v2::PathVector::from)
                .collect(),
        }
    }
}

impl From<v2::UnderlayUpdate> for v3::UnderlayUpdate {
    fn from(value: v2::UnderlayUpdate) -> Self {
        Self {
            announce: value
                .announce
                .into_iter()
                .map(v3::PathVector::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(v3::PathVector::from)
                .collect(),
        }
    }
}

impl v3::TunnelUpdate {
    /// Convert a tunnel update received from the DDMv2 peer `peer`.
    pub fn from_v2(value: v2::TunnelUpdate, peer: &str) -> Self {
        let convert = |x: HashSet<v2::TunnelOrigin>| {
            x.into_iter()
                .map(|t| v3::TunnelOrigin::from_v2(t, peer))
                .collect()
        };
        Self {
            announce: convert(value.announce),
            withdraw: convert(value.withdraw),
        }
    }
}

impl From<v3::TunnelUpdate> for v2::TunnelUpdate {
    fn from(value: v3::TunnelUpdate) -> Self {
        Self {
            announce: value
                .announce
                .into_iter()
                .map(v2::TunnelOrigin::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(v2::TunnelOrigin::from)
                .collect(),
        }
    }
}

impl From<v2::PathVector> for v3::PathVector {
    fn from(value: v2::PathVector) -> Self {
        Self {
            destination: Ipv6Net::new_unchecked(
                value.destination.addr,
                value.destination.len,
            ),
            path: value.path,
        }
    }
}

impl From<v3::PathVector> for v2::PathVector {
    fn from(value: v3::PathVector) -> Self {
        Self {
            destination: v2::Ipv6Prefix {
                addr: value.destination.addr(),
                len: value.destination.width(),
            },
            path: value.path,
        }
    }
}

impl v3::TunnelOrigin {
    /// Convert a tunnel origin received from the DDMv2 peer `peer`, which is
    /// taken to be its originator.
    pub fn from_v2(value: v2::TunnelOrigin, peer: &str) -> Self {
        // TunnelOriginV2 is the DDMv2 wire shape, frozen by protocol
        // contract. If this destructure stops compiling, the V2
        // contract has been violated upstream — there is no
        // #[serde(skip)] escape valve for a wire-format type.
        let v2::TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        Self {
            overlay_prefix: overlay_prefix.into(),
            boundary_addr,
            vni,
            metric,
            path: vec![peer.to_owned()],
        }
    }
}

impl From<v3::TunnelOrigin> for v2::TunnelOrigin {
    fn from(value: v3::TunnelOrigin) -> Self {
        // Compile barrier: adding a v3::TunnelOrigin field fails to
        // bind here, forcing a decision about whether the new
        // field is representable in the V2 wire form. The path is not:
        // DDMv2 tunnel routes carry none.
        let v3::TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
            path: _,
        } = value;
        Self {
            overlay_prefix: overlay_prefix.into(),
            boundary_addr,
            vni,
            metric,
        }
    }
}

impl From<Ipv4Net> for v2::Ipv4Prefix {
    fn from(value: Ipv4Net) -> Self {
        Self {
            addr: value.addr(),
            len: value.width(),
        }
    }
}

impl From<v2::Ipv4Prefix> for Ipv4Net {
    fn from(value: v2::Ipv4Prefix) -> Self {
        Ipv4Net::new_unchecked(value.addr, value.len)
    }
}

impl From<Ipv6Net> for v2::Ipv6Prefix {
    fn from(value: Ipv6Net) -> Self {
        Self {
            addr: value.addr(),
            len: value.width(),
        }
    }
}

impl From<v2::Ipv6Prefix> for Ipv6Net {
    fn from(value: v2::Ipv6Prefix) -> Self {
        Ipv6Net::new_unchecked(value.addr, value.len)
    }
}

impl From<IpNet> for v2::IpPrefix {
    fn from(value: IpNet) -> Self {
        match value {
            IpNet::V4(x) => v2::IpPrefix::V4(x.into()),
            IpNet::V6(x) => v2::IpPrefix::V6(x.into()),
        }
    }
}
impl From<v2::IpPrefix> for IpNet {
    fn from(value: v2::IpPrefix) -> Self {
        match value {
            v2::IpPrefix::V4(x) => IpNet::V4(x.into()),
            v2::IpPrefix::V6(x) => IpNet::V6(x.into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // DDMv2 tunnel routes carry no path. One received from a DDMv2 peer is
    // taken to be originated by that peer, and the path is dropped again when
    // sending to one.
    #[test]
    fn v2_tunnel_origins_are_originated_by_the_peer() {
        let v2_origin = v2::TunnelOrigin {
            overlay_prefix: v2::IpPrefix::V4(v2::Ipv4Prefix {
                addr: "10.0.0.0".parse().unwrap(),
                len: 8,
            }),
            boundary_addr: "fd00:a::1".parse().unwrap(),
            vni: 99,
            metric: 7,
        };
        let pr = v2::PullResponse {
            underlay: None,
            tunnel: Some(HashSet::from([v2_origin])),
        };

        let pr = v3::PullResponse::from_v2(pr, "peer");

        let expected = v3::TunnelOrigin {
            overlay_prefix: "10.0.0.0/8".parse().unwrap(),
            boundary_addr: "fd00:a::1".parse().unwrap(),
            vni: 99,
            metric: 7,
            path: vec!["peer".to_string()],
        };
        assert_eq!(pr.tunnel, Some(HashSet::from([expected.clone()])));
        assert_eq!(v2::TunnelOrigin::from(expected), v2_origin);
    }
}
