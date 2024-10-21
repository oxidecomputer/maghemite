// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{packet, PeerInfo};
use mg_common::lock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[macro_export]
macro_rules! trc {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::trace!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::trace!(
            $self.log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    }
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::debug!(
            $log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::debug!(
            $self.log,
            "{}",
            format!($($args)+),
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    }
}

#[macro_export]
macro_rules! inf {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::info!(
            $log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::info!(
            $self.log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    }
}

#[macro_export]
macro_rules! wrn {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::warn!(
            $log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::warn!(
            $self.log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    };
}

#[macro_export]
macro_rules! err {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::error!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::error!(
            $self.log,
            "{}",
            format!($($args)+);
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    }
}

pub fn update_peer_info(remote: &Arc<Mutex<PeerInfo>>, msg: &packet::Control) {
    let mut r = lock!(remote);
    r.desired_min_tx = Duration::from_micros(msg.desired_min_tx.into());
    r.required_min_rx = Duration::from_micros(msg.required_min_rx.into());
    r.discriminator = msg.my_discriminator;
    r.demand_mode = msg.demand();
    r.detection_multiplier = msg.detect_mult;
}
