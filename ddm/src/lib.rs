// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod admin;
pub mod db;
pub mod discovery;
pub mod exchange;
pub mod oxstats;
pub mod sm;
pub mod sys;
mod util;

#[macro_export]
macro_rules! err {
    ($log:expr, $index:expr, $($args:tt)+) => {
        slog::error!($log, "[{}] {}", $index, format!($($args)+))
    }
}

#[macro_export]
macro_rules! inf {
    ($log:expr, $index:expr, $($args:tt)+) => {
        slog::info!($log, "[{}] {}", $index, format!($($args)+))
    }
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $index:expr, $($args:tt)+) => {
        slog::debug!($log, "[{}] {}", $index, format!($($args)+))
    }
}

#[macro_export]
macro_rules! wrn {
    ($log:expr, $index:expr, $($args:tt)+) => {
        slog::warn!($log, "[{}] {}", $index, format!($($args)+))
    }
}

#[macro_export]
macro_rules! trc {
    ($log:expr, $index:expr, $($args:tt)+) => {
        slog::trace!($log, "[{}] {}", $index, format!($($args)+))
    }
}
