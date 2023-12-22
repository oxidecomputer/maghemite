// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use slog::{Drain, Logger};
use std::fs::File;
use std::io::Write;

pub fn init_logger() -> Logger {
    build_logger(std::io::stdout())
}

pub fn init_file_logger(filename: &str) -> Logger {
    build_logger(File::create(filename).expect("build logger"))
}

pub fn build_logger<W: Write + Send + 'static>(w: W) -> Logger {
    let drain = slog_bunyan::new(w).build().fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x8000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}

#[macro_export]
macro_rules! trc {
    ($self:ident; $($args:tt)+) => {
        slog::trace!(
            $self.log,
            "[{}] {}",
            $self.neighbor.name,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! dbg {
    ($self:ident; $($args:tt)+) => {
        slog::debug!(
            $self.log,
            "[{}] {}",
            $self.neighbor.name,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! inf {
    ($self:ident; $($args:tt)+) => {
        slog::info!(
            $self.log,
            "[{}] {}",
            $self.neighbor.name,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! wrn {
    ($self:ident; $($args:tt)+) => {
        slog::warn!(
            $self.log,
            "[{}] {}",
            $self.neighbor.name,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! err {
    ($self:ident; $($args:tt)+) => {
        slog::error!(
            $self.log,
            "[{}] {}",
            $self.neighbor.name,
            format!($($args)+)
        )
    }
}
