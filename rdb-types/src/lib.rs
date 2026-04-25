// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Core types for routing database operations, shared across maghemite components.
//!
//! This crate provides the fundamental types used for representing network prefixes
//! and routing information. It has minimal dependencies and can be used by clients
//! without pulling in the full RDB implementation.

pub use rdb_types_versions::latest::bfd::*;
pub use rdb_types_versions::latest::neighbor::*;
pub use rdb_types_versions::latest::path::*;
pub use rdb_types_versions::latest::peer::*;
pub use rdb_types_versions::latest::policy::*;
pub use rdb_types_versions::latest::prefix::*;
pub use rdb_types_versions::latest::router::*;
pub use rdb_types_versions::latest::*;
