// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest::net::TunnelOrigin;
use ddm_protocol::v3;

/// The DDMv3 wire form of a tunnel origin.
impl From<TunnelOrigin> for v3::TunnelOrigin {
    fn from(value: TunnelOrigin) -> Self {
        // compilation barrier. a new field must be mapped onto the wire here.
        let TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        Self {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        }
    }
}

/// A tunnel origin received in DDMv3 wire form.
impl From<&v3::TunnelOrigin> for TunnelOrigin {
    fn from(value: &v3::TunnelOrigin) -> Self {
        // compilation barrier. a new wire field must be handled here.
        let &v3::TunnelOrigin {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        } = value;
        Self {
            overlay_prefix,
            boundary_addr,
            vni,
            metric,
        }
    }
}
