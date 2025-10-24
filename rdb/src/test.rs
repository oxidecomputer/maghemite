// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test utilities for rdb tests.

use crate::{Db, error::Error};
use slog::Logger;
use std::sync::atomic::{AtomicU64, Ordering};

/// Get a unique test database path for use in tests.
///
/// This function generates unique database paths using a static counter to avoid
/// conflicts when tests run in parallel. The database will be created in /tmp
/// with a name that includes the test name prefix and a unique counter.
///
/// # Arguments
///
/// * `test_name` - A prefix for the database name (e.g., "rib_test", "bfd_test")
/// * `log` - A logger instance
///
/// # Returns
///
/// A `Db` instance with a unique path, ready for testing
///
/// # Examples
///
/// ```no_run
/// use rdb::test::get_test_db;
/// use mg_common::log::init_file_logger;
///
/// let log = init_file_logger("test.log");
/// let db = get_test_db("my_test", log).expect("create db");
/// ```
pub fn get_test_db(test_name: &str, log: Logger) -> Result<Db, Error> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    std::fs::create_dir_all("/tmp").expect("create tmp dir");
    let db_path = format!(
        "/tmp/{}_{}.db",
        test_name,
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );
    let _ = std::fs::remove_dir_all(&db_path);
    Db::new(&db_path, log)
}
