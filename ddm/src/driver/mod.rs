// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The tasks that drive the pure cores in [`crate::protocol`].
//!
//! One [`interface`] task per interface owns an
//! [`InterfaceSm`](crate::protocol::interface::InterfaceSm) and performs the
//! I/O it asks for. A single [`rib`] hub task owns the route table and the
//! forwarding platform. Interfaces send route events to the hub; the hub sends
//! redistributed updates back out, so the channel topology is a star rather
//! than the mesh the threaded implementation wired up.
//!
//! Everything platform-specific lives here, which is what keeps
//! [`crate::protocol`] free of `target_os` gates.

pub mod interface;
pub mod rib;
