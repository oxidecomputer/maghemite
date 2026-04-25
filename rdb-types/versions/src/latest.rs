// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub use crate::v1::{AddressFamily, ProtocolFilter};

pub mod bfd {
    pub use crate::v1::bfd::{BfdPeerConfig, SessionMode};
}

pub mod neighbor {
    pub use crate::v4::neighbor::{
        BgpNeighborInfo, BgpNeighborParameters, BgpUnnumberedNeighborInfo,
    };
}

pub mod path {
    pub use crate::v5::path::{BgpPathProperties, Path};
}

pub mod peer {
    pub use crate::v1::peer::PeerId;
}

pub mod policy {
    pub use crate::v4::policy::{
        ImportExportPolicy, ImportExportPolicy4, ImportExportPolicy6,
    };
}

pub mod prefix {
    pub use crate::v1::prefix::{Prefix, Prefix4, Prefix6};
}

pub mod router {
    pub use crate::v1::router::BgpRouterInfo;
}
