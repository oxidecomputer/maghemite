// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod db;
pub mod types;

pub use db::Db;
pub use types::*;
pub mod error;

/// The priority routes default to.
pub const DEFAULT_ROUTE_PRIORITY: u64 = 100;
