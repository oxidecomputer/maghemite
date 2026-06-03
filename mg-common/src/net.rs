// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ddm_api_types::net::{IpPrefix, Ipv4Prefix, Ipv6Prefix, TunnelOrigin};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;

/// THIS TYPE IS FOR DDM PROTOCOL VERSION 2. IT SHALL NEVER CHANGE. THIS TYPE
/// CAN BE REMOVED WHEN DDMV2 CLIENTS AND SERVERS NO LONGER EXIST BUT ITS
/// DEFINITION SHALL NEVER CHANGE.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct TunnelOriginV2 {
    pub overlay_prefix: IpPrefix,
    pub boundary_addr: Ipv6Addr,
    pub vni: u32,
    #[serde(default)]
    pub metric: u64,
}

impl From<TunnelOriginV2> for TunnelOrigin {
    fn from(value: TunnelOriginV2) -> Self {
        // TunnelOriginV2 is the DDMv2 wire shape, frozen by protocol
        // contract. If this destructure stops compiling, the V2
        // contract has been violated upstream — there is no
        // #[serde(skip)] escape valve for a wire-format type.
        let TunnelOriginV2 {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        TunnelOrigin {
            overlay_prefix: match overlay_prefix {
                IpPrefix::V4(x) => {
                    IpNet::V4(Ipv4Net::new_unchecked(x.addr, x.len))
                }
                IpPrefix::V6(x) => {
                    IpNet::V6(Ipv6Net::new_unchecked(x.addr, x.len))
                }
            },
            boundary_addr,
            vni,
            metric,
        }
    }
}

impl From<TunnelOrigin> for TunnelOriginV2 {
    fn from(value: TunnelOrigin) -> Self {
        // Compile barrier: adding a TunnelOrigin (latest API) field
        // fails to bind here, forcing a decision about whether the new
        // field is representable in the V2 wire form.
        let TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        TunnelOriginV2 {
            overlay_prefix: match overlay_prefix {
                IpNet::V4(x) => IpPrefix::V4(Ipv4Prefix {
                    addr: x.addr(),
                    len: x.width(),
                }),
                IpNet::V6(x) => IpPrefix::V6(Ipv6Prefix {
                    addr: x.addr(),
                    len: x.width(),
                }),
            },
            boundary_addr,
            vni,
            metric,
        }
    }
}
