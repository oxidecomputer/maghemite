// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod db;
pub mod mrib;
pub mod types;

pub use db::Db;
pub use mrib::Mrib;
pub use types::*;
pub mod bestpath;
pub mod error;
pub mod log;

#[cfg(test)]
mod proptest;

/// The priority routes default to.
pub const DEFAULT_ROUTE_PRIORITY: u64 = u64::MAX;

/// The default RIB Priority of BGP routes.
pub const DEFAULT_RIB_PRIORITY_BGP: u8 = 20;

/// The default RIB Priority of Static routes.
pub const DEFAULT_RIB_PRIORITY_STATIC: u8 = 1;

pub const COMPONENT_RDB: &str = "rdb";
pub const MOD_DB: &str = "database";

/// Test utilities for creating unique test databases
pub mod test;
