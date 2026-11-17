// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Code shared by the [`crate::transit_reconciler`] and
//! [`crate::server_reconciler`] tasks, which converge the forwarding
//! dataplane onto the desired state held in the [`Db`] using the platform
//! backends in `ddm-lower`. They wake on every database change and on a
//! periodic timer, then apply the full desired state idempotently.
//!
//! Each router kind has its own reconciler: transit routers program the
//! switch ASIC through dendrite and server routers program the illumos
//! kernel and OPTE. Tunnel routes only exist on servers, so only the server
//! reconciler handles them; transits keep tunnel routes in the RIB for
//! redistribution.

use crate::db::DbData;
use ddm_lower::{InterfaceName, Route};
use std::collections::HashSet;
use std::time::Duration;

/// The delay between reconciliation passes when the database is quiet.
///
/// The upstream reconcilers that feed this database (sled-agent, mg-lower) are
/// diff-based and make no writes in steady state. This timer is the only thing
/// that heals dataplane drift and retries failed applies.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

/// The underlay routes implied by a [`DbData`] snapshot.
///
/// The db tracks imported routes per path, but the dataplane only knows
/// (destination, nexthop) vectors. The conversion drops the path and the set
/// collapses the duplicates.
pub(crate) fn desired_underlay(data: &DbData) -> HashSet<Route> {
    data.imported
        .iter()
        .map(|r| Route {
            dest: r.destination,
            gw: r.nexthop,
            ifname: InterfaceName::new(r.ifname.clone()),
        })
        .collect()
}
