// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod db;
pub mod rib;
pub mod types;

pub use db::Db;
pub use rib::{Rib, Rib4, Rib6, RibExt};
pub use types::*;
pub mod bestpath;
pub mod error;
pub mod log;

#[cfg(test)]
mod proptest;

/// The priority routes default to.
pub const DEFAULT_ROUTE_PRIORITY: u64 = u64::MAX;

pub const COMPONENT_RDB: &str = "rdb";
pub const MOD_DB: &str = "database";

/// Test utilities for creating unique test databases
pub mod test;
