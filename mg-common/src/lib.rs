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

use oxnet::{IPV4_NET_WIDTH_MAX, IPV6_NET_WIDTH_MAX, IpNet, Ipv4Net, Ipv6Net};

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
