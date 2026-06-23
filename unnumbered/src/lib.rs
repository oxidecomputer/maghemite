// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod bgp;
pub mod error;
mod interface;
pub mod manager;

pub use bgp::{BgpUnnumbered, NdpNeighbor};
pub use error::UnnumberedError;
pub use interface::{
    InterfaceMap, NewUnnumberedInterfaceError, UnnumberedInterface,
    UnnumberedInterfaceError,
};
pub use manager::{
    AddNeighborError, DiscoveredRouterState, InterfaceDetail,
    PendingInterfaceInfo, UnnumberedInterfaceInfo, UnnumberedManager,
    UnnumberedManagerState,
};
