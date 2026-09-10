// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The read side of a running interface driver.
//!
//! The admin API and oximeter never touch a driver's state directly. They hold
//! an [`Interface`] and read the latest [`Status`] the driver published, which
//! is a consistent snapshot taken at the end of one pass through the driver
//! loop.

use crate::protocol::interface::{Input, Status};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch;

/// A handle to one interface driver.
#[derive(Clone)]
pub struct Interface {
    /// Ingress into the driver, for admin events.
    pub ingress: UnboundedSender<Input>,

    /// What the driver last published.
    pub status: watch::Receiver<Status>,

    /// Counters, which the driver and the route hub both write.
    pub stats: Arc<SessionStats>,
}

/// Per-interface counters, exported by oximeter.
///
/// These stay atomics rather than riding the status watch because the route hub
/// writes the imported-prefix gauges while the driver writes everything else.
#[derive(Default)]
pub struct SessionStats {
    // Discovery
    pub solicitations_sent: AtomicU64,
    pub solicitations_received: AtomicU64,
    pub advertisements_sent: AtomicU64,
    pub advertisements_received: AtomicU64,
    pub peer_expirations: AtomicU64,
    pub peer_address_changes: AtomicU64,
    pub peer_established: AtomicU64,

    // Exchange
    pub updates_sent: AtomicU64,
    pub updates_received: AtomicU64,
    pub imported_underlay_prefixes: AtomicU64,
    pub imported_tunnel_endpoints: AtomicU64,
    pub update_send_fail: AtomicU64,
}
