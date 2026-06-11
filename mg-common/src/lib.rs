// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cli;
pub mod log;
pub mod nexus;
pub mod smf;
pub mod stats;
pub mod test;
pub mod thread;

use std::time::Duration;

use oxnet::{IPV4_NET_WIDTH_MAX, IPV6_NET_WIDTH_MAX, IpNet, Ipv4Net, Ipv6Net};

/// Format a Duration for human-readable display.
///
/// Examples: "426d 13h 24m 9s", "3h 12m 5s", "1m 30s 250ms", "500ms"
///
/// Leading zero units are omitted and milliseconds are dropped above 1 hour.
pub fn format_duration_human(d: Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    let millis = d.subsec_millis();

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s {}ms", minutes, seconds, millis)
    } else if seconds > 0 {
        format!("{}s {}ms", seconds, millis)
    } else {
        format!("{}ms", millis)
    }
}

/// Returns `true` if the root cause of `err` is a broken pipe (EPIPE).
pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
}

#[macro_export]
macro_rules! lock {
    ($mtx:expr) => {
        $mtx.lock().expect("lock mutex")
    };
}

#[macro_export]
macro_rules! read_lock {
    ($rwl:expr) => {
        $rwl.read().expect("rwlock read")
    };
}

#[macro_export]
macro_rules! write_lock {
    ($rwl:expr) => {
        $rwl.write().expect("rwlock write")
    };
}

pub trait IpNetExt {
    fn valid_for_rib(&self) -> bool;
}

impl IpNetExt for Ipv4Net {
    /// Check if a prefix contains a subnet that is valid for use in the RIB.
    /// Currently this only checks if the prefix overlaps with Loopback
    /// (127.0.0.0/8) or Multicast (224.0.0.0/4) address space. We deliberately
    /// do not flag Class E (240.0.0.0/4) or Link-Local (169.254.0.0/16)
    /// ranges as invalid, as some networks have deployed these as if they were
    /// standard routable unicast addresses, which we need to handle.
    fn valid_for_rib(&self) -> bool {
        !(self.addr().is_loopback()
            || self.addr().is_multicast()
            || (self.addr().is_unspecified()
                && self.width() == IPV4_NET_WIDTH_MAX))
    }
}

impl IpNetExt for Ipv6Net {
    /// Check if a prefix contains a subnet that is valid for use in the RIB.
    /// Currently this only checks if the prefix carries the Unspecified or
    /// Loopback address (::/128 or ::1/128), Multicast (ff00::/8) or Link-Local
    /// Unicast (fe80::/10) address spaces.
    fn valid_for_rib(&self) -> bool {
        !(self.addr().is_loopback()
            || self.addr().is_multicast()
            || self.addr().is_unicast_link_local()
            || (self.addr().is_unspecified()
                && self.width() == IPV6_NET_WIDTH_MAX))
    }
}

impl IpNetExt for IpNet {
    fn valid_for_rib(&self) -> bool {
        match self {
            IpNet::V4(net4) => net4.valid_for_rib(),
            IpNet::V6(net6) => net6.valid_for_rib(),
        }
    }
}
