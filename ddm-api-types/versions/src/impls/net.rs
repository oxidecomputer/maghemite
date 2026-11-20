// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest::net::TunnelOrigin;
use ddm_protocol::v3;

impl TunnelOrigin {
    /// The DDMv3 wire form of this origin, advertised along `path`.
    pub fn to_wire(self, path: Vec<String>) -> v3::TunnelOrigin {
        // compilation barrier. a new field must be mapped onto the wire here.
        let TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = self;
        v3::TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
            path,
        }
    }
}

/// A tunnel origin received in DDMv3 wire form, without the path it was
/// advertised along.
impl From<&v3::TunnelOrigin> for TunnelOrigin {
    fn from(value: &v3::TunnelOrigin) -> Self {
        // compilation barrier. a new wire field must be handled here.
        let &v3::TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
            path: _,
        } = value;
        Self {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        }
    }
}
