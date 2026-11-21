// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Protocol types for DDM.

use oxnet::{IpNet, Ipv4Net, Ipv6Net};

pub mod v2;
pub mod v3;

// DDMv2 tunnel routes carry no path, so converting them to DDMv3 needs the
// peer they were received from. They are treated as originated by that peer.
// DDMv2 also does not distinguish bootstrap routes from underlay routes.
// Conversions handle this by mapping both bootstrap/underlay -> underlay during
// downgrade and by handling all v2 underlay routes as underlay.
// All conversions use manual destructuring to prevent compilation if types are
// modified, which should never happen after a DDM version is published.

impl v3::Update {
    /// Convert an update received from the DDMv2 peer `peer`.
    pub fn from_v2(value: v2::Update, peer: &str) -> Self {
        let v2::Update { underlay, tunnel } = value;
        Self {
            underlay: underlay.map(v3::UnderlayUpdate::from),
            bootstrap: None,
            tunnel: tunnel.map(|t| v3::TunnelUpdate::from_v2(t, peer)),
        }
    }
}

impl From<v3::Update> for v2::Update {
    fn from(value: v3::Update) -> Self {
        let v3::Update {
            underlay,
            bootstrap,
            tunnel,
        } = value;
        let underlay = match (underlay, bootstrap) {
            (None, None) => None,
            (None, Some(b)) => Some(v3::UnderlayUpdate {
                announce: b.announce,
                withdraw: b.withdraw,
            }),
            (Some(u), None) => Some(u),
            (Some(mut u), Some(b)) => {
                u.announce.extend(b.announce);
                u.withdraw.extend(b.withdraw);
                Some(u)
            }
        }
        .map(v2::UnderlayUpdate::from);
        Self {
            tunnel: tunnel.map(v2::TunnelUpdate::from),
            underlay,
        }
    }
}

impl v3::PullResponse {
    /// Convert a pull response received from the DDMv2 peer `peer`.
    pub fn from_v2(value: v2::PullResponse, peer: &str) -> Self {
        let v2::PullResponse { underlay, tunnel } = value;
        Self {
            underlay: underlay
                .map(|x| x.into_iter().map(v3::PathVector::from).collect()),
            bootstrap: None,
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
        let v3::PullResponse {
            underlay,
            bootstrap,
            tunnel,
        } = value;
        let underlay = match (underlay, bootstrap) {
            (None, None) => None,
            (None, Some(b)) => Some(b),
            (Some(u), None) => Some(u),
            (Some(mut u), Some(b)) => {
                u.extend(b);
                Some(u)
            }
        };
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
        let v3::UnderlayUpdate { announce, withdraw } = value;
        Self {
            announce: announce.into_iter().map(v2::PathVector::from).collect(),
            withdraw: withdraw.into_iter().map(v2::PathVector::from).collect(),
        }
    }
}

impl From<v2::UnderlayUpdate> for v3::UnderlayUpdate {
    fn from(value: v2::UnderlayUpdate) -> Self {
        let v2::UnderlayUpdate { announce, withdraw } = value;
        Self {
            announce: announce.into_iter().map(v3::PathVector::from).collect(),
            withdraw: withdraw.into_iter().map(v3::PathVector::from).collect(),
        }
    }
}

impl v3::TunnelUpdate {
    /// Convert a tunnel update received from the DDMv2 peer `peer`.
    pub fn from_v2(value: v2::TunnelUpdate, peer: &str) -> Self {
        let v2::TunnelUpdate { announce, withdraw } = value;
        Self {
            announce: announce
                .into_iter()
                .map(|t| v3::TunnelOrigin::from_v2(t, peer))
                .collect(),
            withdraw: withdraw
                .into_iter()
                .map(|t| v3::TunnelOrigin::from_v2(t, peer))
                .collect(),
        }
    }
}

impl From<v3::TunnelUpdate> for v2::TunnelUpdate {
    fn from(value: v3::TunnelUpdate) -> Self {
        let v3::TunnelUpdate { announce, withdraw } = value;
        Self {
            announce: announce
                .into_iter()
                .map(v2::TunnelOrigin::from)
                .collect(),
            withdraw: withdraw
                .into_iter()
                .map(v2::TunnelOrigin::from)
                .collect(),
        }
    }
}

impl From<v2::PathVector> for v3::PathVector {
    fn from(value: v2::PathVector) -> Self {
        let v2::PathVector { destination, path } = value;
        Self {
            destination: destination.into(),
            path,
        }
    }
}

impl From<v3::PathVector> for v2::PathVector {
    fn from(value: v3::PathVector) -> Self {
        let v3::PathVector { destination, path } = value;
        Self {
            destination: v2::Ipv6Prefix {
                addr: destination.addr(),
                len: destination.width(),
            },
            path,
        }
    }
}

impl v3::TunnelOrigin {
    /// Convert a tunnel origin received from the DDMv2 peer `peer`, which is
    /// taken to be its originator.
    pub fn from_v2(value: v2::TunnelOrigin, peer: &str) -> Self {
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
    use std::collections::HashSet;

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
