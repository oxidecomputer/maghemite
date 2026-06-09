// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Protocol types for DDM.

use oxnet::{IpNet, Ipv4Net, Ipv6Net};

pub mod v2;
pub mod v3;

impl From<v2::Update> for v3::Update {
    fn from(value: v2::Update) -> Self {
        Self {
            tunnel: value.tunnel.map(v3::TunnelUpdate::from),
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

impl From<v2::PullResponse> for v3::PullResponse {
    fn from(value: v2::PullResponse) -> Self {
        Self {
            underlay: value
                .underlay
                .map(|x| x.into_iter().map(v3::PathVector::from).collect()),
            tunnel: value
                .tunnel
                .map(|x| x.into_iter().map(v3::TunnelOrigin::from).collect()),
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

impl From<v2::TunnelUpdate> for v3::TunnelUpdate {
    fn from(value: v2::TunnelUpdate) -> Self {
        v3::TunnelUpdate {
            announce: value
                .announce
                .into_iter()
                .map(v3::TunnelOrigin::from)
                .collect(),
            withdraw: value
                .withdraw
                .into_iter()
                .map(v3::TunnelOrigin::from)
                .collect(),
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

impl From<v2::TunnelOrigin> for v3::TunnelOrigin {
    fn from(value: v2::TunnelOrigin) -> Self {
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
        }
    }
}

impl From<v3::TunnelOrigin> for v2::TunnelOrigin {
    fn from(value: v3::TunnelOrigin) -> Self {
        // Compile barrier: adding a TunnelOrigin (latest API) field
        // fails to bind here, forcing a decision about whether the new
        // field is representable in the V2 wire form.
        let v3::TunnelOrigin {
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
