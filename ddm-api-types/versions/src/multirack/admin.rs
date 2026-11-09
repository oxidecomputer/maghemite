// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The prefix a transit router originates on behalf of its whole rack.
///
/// It is advertised to transit peers as an underlay route, so routers in
/// other racks learn it as an ordinary underlay prefix.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub struct RackPrefix {
    pub prefix: Ipv6Net,
}
