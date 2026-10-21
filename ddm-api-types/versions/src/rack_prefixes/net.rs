// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use oxnet::SocketAddrV6Json;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// The admin API carries these in a map keyed by the rack prefix, so a prefix
// cannot be given two join addresses in one request. A set of
// `(prefix, join address)` structs would allow that, since set members are
// distinct whenever any field differs. This is a struct rather than a bare
// `Option` because generated clients drop the nullability of an `Option` used
// directly as a map value.

/// What a transit router originates along with one of its rack prefixes.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
pub struct RackPrefixInfo {
    /// The address other racks use to join this rack, if any.
    pub multi_rack_join_addr: Option<SocketAddrV6Json>,
}
