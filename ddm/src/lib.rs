pub mod admin;
pub mod db;
pub mod discovery;
mod exchange;
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
