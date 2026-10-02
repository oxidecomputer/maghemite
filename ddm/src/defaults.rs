// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

pub const SOLICIT_INTERVAL: Duration = Duration::from_millis(2000);
pub const EXPIRE_THRESHOLD: Duration = Duration::from_millis(5000);
pub const DISCOVERY_READ_TIMEOUT: Duration = Duration::from_millis(1000);
pub const IP_ADDR_WAIT: Duration = Duration::from_millis(1000);
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_millis(3000);

pub const EXCHANGE_TCP_PORT: u16 = 0xdddd;

pub const fn millis_u64(d: Duration) -> u64 {
    let x = d.as_millis();
    assert!(x <= u64::MAX as u128);
    x as u64
}
