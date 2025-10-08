// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test utilities and macros for use across multiple crates.

use crate::lock;
use slog::{error, info, Logger};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const DEFAULT_INTERVAL: u64 = 1;
pub const DEFAULT_ITERATIONS: u64 = 30;

/// Cross-platform file locking trait using libc's flock(2)
trait FileLockExt {
    fn lock_exclusive(&self) -> std::io::Result<()>;
}

impl FileLockExt for File {
    fn lock_exclusive(&self) -> std::io::Result<()> {
        let fd = self.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

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

struct ManagedIp {
    address: IpAddr,
    installed: bool,
    lockfile: Option<File>,
}

/// RAII guard that ensures proper cleanup of allocated IP addresses
/// when dropped, even if the test panics.
pub struct IpAllocation {
    pub addresses: Vec<IpAddr>,
    pub manager: Arc<Mutex<LoopbackIpManager>>,
}

impl Drop for IpAllocation {
    fn drop(&mut self) {
        let mut manager = lock!(self.manager);
        // Uninstall only the specific addresses this allocation is responsible for
        manager.uninstall_addresses(&self.addresses);
    }
}

pub struct LoopbackIpManager {
    ips: Vec<ManagedIp>,
    ifname: String,
    log: Logger,
}

impl LoopbackIpManager {
    pub fn new(ifname: &str, log: Logger) -> Self {
        Self {
            ips: Vec::new(),
            ifname: ifname.to_string(),
            log,
        }
    }

    pub fn add(&mut self, addresses: &[IpAddr]) {
        for addr in addresses {
            // Only add if not already present
            if !self.ips.iter().any(|ip| ip.address == *addr) {
                self.ips.push(ManagedIp {
                    address: *addr,
                    installed: false,
                    lockfile: None,
                });
            }
        }
    }

    /// Allocate IP addresses and return a guard that will clean them up on drop.
    /// This ensures proper cleanup even if the test panics.
    pub fn allocate(
        manager: Arc<Mutex<Self>>,
        addresses: &[IpAddr],
    ) -> Result<IpAllocation, std::io::Error> {
        // Install the addresses
        {
            let mut mgr = lock!(manager);
            mgr.add(addresses);
            mgr.install()?;
        }

        // Return guard that will clean up on drop
        Ok(IpAllocation {
            addresses: addresses.to_vec(),
            manager,
        })
    }
}

// Helper functions for lockfile-based reference counting
fn flock(path: &str) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock_exclusive()?;
    Ok(file)
}

fn read_refcount(file: &mut File) -> u32 {
    let mut contents = String::new();
    file.seek(SeekFrom::Start(0)).ok();
    file.read_to_string(&mut contents).ok();
    contents.trim().parse().unwrap_or(0)
}

fn write_refcount(file: &mut File, count: u32) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    write!(file, "{}", count)?;
    file.flush()?;
    Ok(())
}

impl LoopbackIpManager {
    pub fn install(&mut self) -> Result<(), std::io::Error> {
        let ifname = self.ifname.clone();
        let log = self.log.clone();

        for ip in &mut self.ips {
            if !ip.installed {
                Self::install_single_ip_static(&ifname, &log, ip)?;
            }
        }
        Ok(())
    }

    /// Install a single IP address with proper refcount management
    /// Skips 127.0.0.1 as it's always present on loopback interfaces
    fn install_single_ip_static(
        ifname: &str,
        log: &Logger,
        ip: &mut ManagedIp,
    ) -> Result<(), std::io::Error> {
        // Skip 127.0.0.1 as it's always present on loopback interfaces by default
        if ip.address.to_string() == "127.0.0.1" {
            info!(log, "skipping 127.0.0.1 (always present on loopback)");
            ip.installed = true; // Mark as installed but don't create lockfile
            return Ok(());
        }

        // 1. Acquire lock for this IP
        let lockfile_path = format!("/tmp/maghemite-ip-{}.lock", ip.address);
        let mut lockfile = flock(&lockfile_path)?;

        // 2. Read current refcount
        let refcount = read_refcount(&mut lockfile);

        // 3. If refcount == 0, actually install the IP
        if refcount == 0 {
            Self::add_ip_to_system(ifname, log, ip)?;
        }

        // 4. Increment refcount and write back
        let new_refcount = refcount + 1;
        info!(
            log,
            "{}: increment refcount {refcount}->{new_refcount}", ip.address,
        );
        write_refcount(&mut lockfile, new_refcount)?;

        // 5. Update our state
        ip.installed = true;
        ip.lockfile = Some(lockfile);

        Ok(())
    }

    /// Add IP to the system using platform-specific commands
    fn add_ip_to_system(
        ifname: &str,
        log: &Logger,
        ip: &ManagedIp,
    ) -> Result<(), std::io::Error> {
        let addr_str = format!("{}/32", ip.address);

        #[cfg(target_os = "illumos")]
        let output = {
            let ip_descr = format!("{}", ip.address).replace('.', "dot");
            let addr_obj = format!("{}/test{}", ifname, ip_descr);
            Command::new("pfexec")
                .args([
                    "ipadm",
                    "create-addr",
                    "-T",
                    "static",
                    "-a",
                    &addr_str,
                    &addr_obj,
                ])
                .output()?
        };

        #[cfg(target_os = "linux")]
        let output = Command::new("sudo")
            .args(&["ip", "addr", "add", &addr_str, "dev", ifname])
            .output()?;

        #[cfg(target_os = "macos")]
        let output = Command::new("sudo")
            .args(["ifconfig", ifname, "alias", &addr_str])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "Address already exists/assigned" is ok - another process beat us to it
            if !stderr.to_lowercase().contains("already") {
                error!(log, "failed to install {}: {stderr}", ip.address);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to install {}", ip.address),
                ));
            }
        }

        info!(log, "added {} to system", ip.address);
        Ok(())
    }

    /// Uninstall specific addresses (used by IpAllocation guard)
    pub fn uninstall_addresses(&mut self, addresses: &[IpAddr]) {
        for addr in addresses {
            self.uninstall_single_ip(*addr);
        }
    }

    /// Uninstall all managed addresses
    pub fn uninstall(&mut self) {
        let addresses: Vec<IpAddr> =
            self.ips.iter().map(|ip| ip.address).collect();
        self.uninstall_addresses(&addresses);
    }

    /// Uninstall a single IP address with proper refcount management
    /// Skips 127.0.0.1 as it should always remain on loopback interfaces
    fn uninstall_single_ip(&mut self, target_addr: IpAddr) {
        // Skip 127.0.0.1 as it should always remain on loopback interfaces
        if target_addr.to_string() == "127.0.0.1" {
            info!(
                self.log,
                "skipping 127.0.0.1 cleanup (always present on loopback)"
            );
            // Just mark as uninstalled in our tracking, but don't touch the system
            for ip in &mut self.ips {
                if ip.address == target_addr {
                    ip.installed = false;
                    ip.lockfile = None; // No lockfile was created for 127.0.0.1
                    break;
                }
            }
            return;
        }

        for ip in &mut self.ips {
            if ip.address == target_addr && ip.installed {
                if let Some(mut lockfile) = ip.lockfile.take() {
                    let lockfile_path =
                        format!("/tmp/maghemite-ip-{}.lock", ip.address);

                    // Read current refcount
                    let refcount = read_refcount(&mut lockfile);

                    // Decrement refcount and write back
                    let new_refcount = refcount.saturating_sub(1);
                    info!(
                        self.log,
                        "{}: decrement refcount {refcount}->{new_refcount}",
                        ip.address,
                    );

                    if new_refcount == 0 {
                        // Remove the IP from the system and delete the lockfile
                        Self::remove_ip_from_system_static(
                            &self.ifname,
                            &self.log,
                            ip,
                        );

                        // Remove the lockfile completely when refcount reaches 0
                        drop(lockfile); // Release the file lock
                        if let Err(e) = std::fs::remove_file(&lockfile_path) {
                            error!(
                                self.log,
                                "failed to remove lockfile {}: {e}",
                                lockfile_path
                            );
                        } else {
                            info!(
                                self.log,
                                "removed lockfile {}", lockfile_path
                            );
                        }
                    } else {
                        // Write back the decremented refcount
                        let _ = write_refcount(&mut lockfile, new_refcount);
                    }
                }

                // Always update our state
                ip.installed = false;
                ip.lockfile = None;
                info!(self.log, "uninstalled {}", ip.address);
                break;
            }
        }
    }

    /// Remove IP from the system using platform-specific commands
    fn remove_ip_from_system_static(
        ifname: &str,
        log: &Logger,
        ip: &ManagedIp,
    ) {
        #[cfg(target_os = "illumos")]
        let output = {
            let ip_descr = format!("{}", ip.address).replace('.', "dot");
            let addr_obj = format!("{}/test{}", ifname, ip_descr);
            Command::new("pfexec")
                .args(["ipadm", "delete-addr", &addr_obj])
                .output()
        };

        #[cfg(target_os = "linux")]
        let output = {
            let addr_str = format!("{}/32", ip.address);
            Command::new("sudo")
                .args(&["ip", "addr", "del", &addr_str, "dev", ifname])
                .output()
        };

        #[cfg(target_os = "macos")]
        let output = Command::new("sudo")
            .args(["ifconfig", ifname, "-alias", &ip.address.to_string()])
            .output();

        match output {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let lc = stderr.to_lowercase();

                    // These error conditions are acceptable (IP wasn't there to begin with)
                    if !lc.contains("not found") && !lc.contains("can't assign")
                    {
                        error!(
                            log,
                            "failed to remove {} from system: {stderr}",
                            ip.address
                        );
                        return;
                    }
                }
                info!(log, "removed {} from system", ip.address);
            }
            Err(e) => {
                error!(
                    log,
                    "failed to execute remove command for {}: {e}", ip.address
                );
            }
        }
    }
}
