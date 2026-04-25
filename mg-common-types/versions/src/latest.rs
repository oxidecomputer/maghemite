// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod net {
    pub use crate::v1::net::IpPrefix;
    pub use crate::v1::net::Ipv4Prefix;
    pub use crate::v1::net::Ipv6Prefix;
    pub use crate::v1::net::TunnelOrigin;
}
