// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The route hub: one task owning the route table and the forwarding platform.
//!
//! Serializing route work through a single task is what lets the interface
//! drivers stay ignorant of each other. It also means no interface ever blocks
//! on a route-socket call, an OPTE ioctl, or a dpd request.

use crate::db::Db;
use crate::protocol::interface::Input;
use crate::protocol::rib::RibEvent;
use crate::sm::{Config, SessionStats};
use crate::{dbg, err};
use slog::Logger;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// A [`RibEvent`] plus what the hub needs to execute and redistribute it.
pub struct HubEvent {
    pub event: RibEvent,

    /// The interface that produced the event. Redistribution skips it, so a
    /// router never sends a prefix back the way it came.
    pub origin: usize,

    /// The producing interface's config, with addressing resolved.
    /// [`crate::sys::program`] reads the interface name and dpd settings from
    /// it.
    pub config: Config,

    /// The producing interface's stats, where the imported-prefix gauges live.
    pub stats: Arc<SessionStats>,
}

pub fn spawn(
    db: Db,
    peers: Vec<UnboundedSender<Input>>,
    mut rx: UnboundedReceiver<HubEvent>,
    rt: Arc<tokio::runtime::Handle>,
    log: Logger,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(hev) = rx.recv().await {
            let HubEvent {
                event,
                origin,
                config,
                stats,
            } = hev;

            let imported = matches!(event, RibEvent::Update { .. });
            let if_name = config.if_name.clone();
            let mut out = db.apply(event);
            let redistribute = out.redistribute.take();

            let plog = log.clone();
            let prt = rt.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                crate::sys::program(&out, &config, &prt, &plog);
            })
            .await
            {
                err!(log, if_name, "route programming: {e}");
            }

            if let Some(push) = redistribute {
                dbg!(
                    log,
                    if_name,
                    "redistributing update to {} peers",
                    peers.len().saturating_sub(1)
                );
                for (i, tx) in peers.iter().enumerate() {
                    if i == origin {
                        continue;
                    }
                    if let Err(e) =
                        tx.send(Input::Redistribute(Box::new(push.clone())))
                    {
                        err!(log, if_name, "redistribute to {i}: {e}");
                    }
                }
            }

            // Only updates move these gauges, matching the threaded
            // implementation, which left them alone on peer expiry.
            if imported {
                stats
                    .imported_underlay_prefixes
                    .store(db.imported_count() as u64, Ordering::Relaxed);
                stats.imported_tunnel_endpoints.store(
                    db.imported_tunnel_count() as u64,
                    Ordering::Relaxed,
                );
            }
        }
    })
}
