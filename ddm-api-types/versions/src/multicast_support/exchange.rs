// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exchange (wire) types added in API version 3 (MULTICAST_SUPPORT),
//! which carries the `ddm_protocol::v4` wire types.
//!
//! These are re-exports of the plain wire types defined in the
//! [`ddm_protocol`] crate, mirroring how `PathVector` and `TunnelOrigin`
//! re-export their `ddm_protocol::v3` counterparts. Keeping a single
//! definition avoids a rich/wire split for path vectors, and peer-supplied
//! routes are stored in this plain form without re-validation.

pub use ddm_protocol::v4::{MulticastPathHop, MulticastPathVector};
