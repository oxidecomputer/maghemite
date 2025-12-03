// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{PeerInfo, packet};
use mg_common::lock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn update_peer_info(remote: &Arc<Mutex<PeerInfo>>, msg: &packet::Control) {
    let mut r = lock!(remote);
    r.desired_min_tx = Duration::from_micros(msg.desired_min_tx.into());
    r.required_min_rx = Duration::from_micros(msg.required_min_rx.into());
    r.discriminator = msg.my_discriminator;
    r.demand_mode = msg.demand();
    r.detection_multiplier = msg.detect_mult;
}
