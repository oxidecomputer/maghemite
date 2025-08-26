// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test utilities and macros for use across multiple crates.

use std::process::Command;
use std::{collections::HashMap, net::IpAddr};

pub const DEFAULT_INTERVAL: u64 = 1;
pub const DEFAULT_ITERATIONS: u64 = 30;

#[macro_export]
macro_rules! wait_for_eq {
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr, $msg:tt) => {
        wait_for!($lhs == $rhs, $period, $count, $msg);
    };
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr) => {
        wait_for!($lhs == $rhs, $period, $count);
    };
    ($lhs:expr, $rhs:expr, $msg:tt) => {
        wait_for!(
            $lhs == $rhs,
            mg_common::test::DEFAULT_INTERVAL,
            mg_common::test::DEFAULT_ITERATIONS,
            $msg
        );
    };
    ($lhs:expr, $rhs:expr) => {
        wait_for!(
            $lhs == $rhs,
            mg_common::test::DEFAULT_INTERVAL,
            mg_common::test::DEFAULT_ITERATIONS
        );
    };
}

#[macro_export]
macro_rules! wait_for_neq {
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr, $msg:tt) => {
        wait_for!($lhs != $rhs, $period, $count, $msg);
    };
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr) => {
        wait_for!($lhs != $rhs, $period, $count);
    };
    ($lhs:expr, $rhs:expr, $msg:tt) => {
        wait_for!(
            $lhs != $rhs,
            mg_common::test::DEFAULT_INTERVAL,
            mg_common::test::DEFAULT_ITERATIONS,
            $msg
        );
    };
    ($lhs:expr, $rhs:expr) => {
        wait_for!(
            $lhs != $rhs,
            mg_common::test::DEFAULT_INTERVAL,
            mg_common::test::DEFAULT_ITERATIONS
        );
    };
}

#[macro_export]
macro_rules! wait_for {
    ($cond:expr, $period:expr, $count:expr, $msg:tt) => {
        let mut ok = false;
        for _ in 0..$count {
            if $cond {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs($period));
        }
        if !ok {
            assert!($cond, $msg);
        }
    };
    ($cond:expr, $period:expr, $count:expr) => {
        let mut ok = false;
        for _ in 0..$count {
            if $cond {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs($period));
        }
        if !ok {
            assert!($cond);
        }
    };
    ($cond:expr, $msg:tt) => {
        wait_for!(
            $cond,
            mg_common::test::DEFAULT_INTERVAL,
            mg_common::test::DEFAULT_ITERATIONS,
            $msg
        );
    };
    ($cond:expr) => {
        wait_for!(
            $cond,
            mg_common::test::DEFAULT_INTERVAL,
            mg_common::test::DEFAULT_ITERATIONS
        );
    };
}

#[macro_export]
macro_rules! parse {
    ($x:expr, $err:expr) => {
        $x.parse().expect($err)
    };
}

#[macro_export]
macro_rules! ip {
    ($x:expr) => {
        parse!($x, "ip address")
    };
}

#[macro_export]
macro_rules! cidr {
    ($x:expr) => {
        parse!($x, "ip cidr")
    };
}

#[macro_export]
macro_rules! sockaddr {
    ($x:expr) => {
        parse!($x, "socket address")
    };
}

pub struct LoopbackIpManager {
    addresses: HashMap<IpAddr, bool>,
    ifname: String,
}

impl LoopbackIpManager {
    pub fn new(ifname: &str) -> Self {
        Self {
            addresses: HashMap::new(),
            ifname: ifname.to_string(),
        }
    }

    pub fn add(&mut self, addresses: &[IpAddr]) {
        for addr in addresses.iter() {
            self.addresses.insert(*addr, false);
        }
    }

    #[cfg(target_os = "illumos")]
    pub fn install(&mut self) -> Result<(), std::io::Error> {
        for (address, installed) in self.addresses.iter_mut() {
            if !*installed {
                let addr_str = format!("{address}/32");
                let addr_desc = format!("{}/test-{address}", &self.ifname);
                let output = Command::new("pfexec")
                    .args(&[
                        "ipadm",
                        "create-addr",
                        "-T",
                        "static",
                        "-a",
                        &addr_str,
                        &addr_desc,
                    ])
                    .output()
                    .expect("failed to execute command");

                if output.status.success() {
                    *installed = true;
                    continue;
                }

                let stderr = String::from_utf8_lossy(&output.stderr);

                // "Address already exists" => illumos
                if stderr.to_lowercase().contains("already") {
                    *installed = true;
                    continue;
                }

                eprintln!("failed to install {address}: {stderr}");
                *installed = false;
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn install(&mut self) -> Result<(), std::io::Error> {
        if !*installed {
            let addr_str = format!("{address}/32");
            let output = Command::new("sudo")
                .args(&["ip", "addr", "add", &addr_str, "dev", &self.ifname])
                .output()
                .expect("failed to execute command");

            if output.status.success() {
                *installed = true;
                continue;
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            // "Address already exists" => illumos
            // "Address already assigned" => linux
            if stderr.to_lowercase().contains("already") {
                *installed = true;
                continue;
            }

            eprintln!("failed to install {address}: {stderr}");
            *installed = false;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub fn install(&mut self) -> Result<(), std::io::Error> {
        for (address, installed) in self.addresses.iter_mut() {
            let addr_str = format!("{address}/32");
            if !*installed {
                let output = Command::new("sudo")
                    .args(["ifconfig", &self.ifname, "alias", &addr_str])
                    .output()
                    .expect("failed to execute command");

                if output.status.success() {
                    *installed = true;
                    continue;
                }

                let stderr = String::from_utf8_lossy(&output.stderr);

                // macos returns 0 when trying to add a pre-existing addr
                if stderr.to_lowercase().contains("already") {
                    *installed = true;
                    continue;
                }

                eprintln!("failed to install {address}: {stderr}");
                *installed = false;
            }
        }
        Ok(())
    }

    #[cfg(target_os = "illumos")]
    pub fn uninstall(&mut self) {
        for (address, installed) in self.addresses.iter_mut() {
            if *installed {
                let addr_desc = format!("{}/test-{address}", &self.ifname);

                let output = Command::new("pfexec")
                    .args(&["ipadm", "delete-addr", &addr_desc])
                    .output()
                    .expect("failed to execute command");

                if output.status.success() {
                    *installed = false;
                    continue;
                }

                let stderr = String::from_utf8_lossy(&output.stderr);

                // illumos => "could not delete address: Object not found"
                if stderr.to_lowercase().contains("not found") {
                    *installed = false;
                    continue;
                }

                eprintln!("failed to uninstall {address}: {stderr}");
                // not changing the installed status upon unexpected failure
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn uninstall(&mut self) {
        for (address, installed) in self.addresses.iter_mut() {
            if *installed {
                let addr_str = format!("{address}/32");
                let output = Command::new("sudo")
                    .args(&[
                        "ip",
                        "addr",
                        "del",
                        &addr_str,
                        "dev",
                        &self.ifname,
                    ])
                    .output()
                    .expect("failed to execute command");

                if output.status.success() {
                    *installed = false;
                    continue;
                }

                let stderr = String::from_utf8_lossy(&output.stderr);

                // illumos => "could not delete address: Object not found"
                if stderr.to_lowercase().contains("not found") {
                    *installed = false;
                    continue;
                }

                eprintln!("failed to uninstall {address}: {stderr}");
                // not changing the installed status upon unexpected failure
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub fn uninstall(&mut self) {
        for (address, installed) in self.addresses.iter_mut() {
            if *installed {
                let output = Command::new("sudo")
                    .args([
                        "ifconfig",
                        &self.ifname,
                        "-alias",
                        &address.to_string(),
                    ])
                    .output()
                    .expect("failed to execute command");

                if output.status.success() {
                    *installed = false;
                    continue;
                }

                let stderr = String::from_utf8_lossy(&output.stderr);

                // illumos => "could not delete address: Object not found"
                if stderr.to_lowercase().contains("not found") {
                    *installed = false;
                    continue;
                }

                eprintln!("failed to uninstall {address}: {stderr}");
                // not changing the installed status upon unexpected failure
            }
        }
    }
}

impl Drop for LoopbackIpManager {
    fn drop(&mut self) {
        self.uninstall();
    }
}
