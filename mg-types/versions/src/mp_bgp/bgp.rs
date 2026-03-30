// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::IpAddr;

use bgp::params::NeighborResetOp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v1;

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct NeighborResetRequest {
    pub asn: u32,
    pub addr: IpAddr,
    pub op: NeighborResetOp,
}

impl From<v1::bgp::NeighborResetRequest> for NeighborResetRequest {
    fn from(req: v1::bgp::NeighborResetRequest) -> Self {
        Self {
            asn: req.asn,
            addr: req.addr,
            op: req.op.into(),
        }
    }
}
