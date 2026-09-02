// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test utilities for rdb tests.

use crate::types::{RouterId, RouterInfo};
use crate::{Db, RouterDb, error::Error};
use client_common::eprintln_nopipe;
use slog::Logger;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};

/// A test database wrapper that automatically cleans up the database directory
/// when dropped, but only if the test succeeded.
///
/// If the test panics (fails), the database is left in /tmp for debugging.
/// This allows you to examine the database state after a test failure.
///
/// The wrapper holds a [`Db`] with a single `"default"` router and implements
/// `Deref` and `DerefMut` to that router's [`RouterDb`], so you can use it
/// like a regular `RouterDb`.
///
/// Cloning a `TestDb` clones the underlying handles (which is cheap since
/// they use `Arc` internally) but shares the same database path. Only the
/// last `TestDb` instance to be dropped will clean up the database.
#[derive(Clone)]
pub struct TestDb {
    db: Db,
    router: RouterDb,
    path: String,
}

impl TestDb {
    /// Get the underlying Db reference
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Get the default router's RouterDb reference
    pub fn router(&self) -> &RouterDb {
        &self.router
    }

    /// Get the database path
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Deref for TestDb {
    type Target = RouterDb;

    fn deref(&self) -> &Self::Target {
        &self.router
    }
}

impl DerefMut for TestDb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.router
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Only clean up if the test succeeded (thread is not panicking)
        // This leaves the database available for debugging after failures
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.path);
        } else {
            eprintln_nopipe!("Test failed - database left at: {}", self.path);
        }
    }
}

/// Get a unique test database for use in tests.
///
/// This function generates unique database paths using a static counter to avoid
/// conflicts when tests run in parallel. The database will be created in /tmp
/// with a name that includes the test name prefix and a unique counter.
///
/// Returns a `TestDb` wrapper that automatically cleans up the database directory
/// when dropped, **but only if the test succeeds**. Failed tests leave their
/// databases in /tmp for debugging.
///
/// # Arguments
///
/// * `test_name` - A prefix for the database name (e.g., "rib_test", "bfd_test")
/// * `log` - A logger instance
///
/// # Returns
///
/// A `TestDb` instance with a unique path, ready for testing. The database will
/// be automatically cleaned up on success, or left for debugging on failure.
///
/// # Examples
///
/// ```no_run
/// use rdb::test::get_test_db;
/// use rdb::StaticRouteKey;
/// use mg_common::log::init_file_logger;
/// use std::net::{IpAddr, Ipv4Addr};
///
/// let log = init_file_logger("test.log");
/// let db = get_test_db("my_test", log).expect("create db");
///
/// // Create some example static routes
/// let routes = vec![
///     StaticRouteKey {
///         prefix: "10.0.0.0/24".parse().unwrap(),
///         nexthop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///         vlan_id: None,
///         rib_priority: 0,
///     },
/// ];
///
/// // Use db like a regular Db - it derefs automatically
/// db.add_static_routes(&routes).unwrap();
///
/// // Query the routes back
/// let stored_routes = db.get_static(None).unwrap();
/// assert_eq!(stored_routes.len(), 1);
///
/// // Database cleaned up automatically on success, left for debugging on failure
/// ```
pub fn get_test_db(test_name: &str, log: Logger) -> Result<TestDb, Error> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    std::fs::create_dir_all("/tmp").expect("create tmp dir");

    // Include process ID to avoid collisions between parallel test processes
    let db_path = format!(
        "/tmp/{}_{}_{}.db",
        test_name,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );

    // Clean up stale database if it exists (e.g., from a crashed test run)
    if std::path::Path::new(&db_path).exists() {
        let _ = std::fs::remove_dir_all(&db_path);
    }

    let db = Db::new(&db_path, log)?;
    let router = db.create_router(RouterInfo {
        id: RouterId::new_random(),
        name: "default".to_string(),
        tep: std::net::Ipv6Addr::UNSPECIFIED,
    })?;
    Ok(TestDb {
        db,
        router,
        path: db_path,
    })
}
