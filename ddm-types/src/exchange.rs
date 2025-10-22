// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use mg_common::net::Ipv6Prefix;
use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct PathVector {
    pub destination: Ipv6Net,
    pub path: Vec<String>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct PathVectorV2 {
    pub destination: Ipv6Prefix,
    pub path: Vec<String>,
}

impl From<PathVectorV2> for PathVector {
    fn from(value: PathVectorV2) -> Self {
        PathVector {
            destination: Ipv6Net::new_unchecked(
                value.destination.addr,
                value.destination.len,
            ),
            path: value.path,
        }
    }
}

impl From<PathVector> for PathVectorV2 {
    fn from(value: PathVector) -> Self {
        PathVectorV2 {
            destination: Ipv6Prefix {
                addr: value.destination.addr(),
                len: value.destination.width(),
            },
            path: value.path,
        }
    }
}
