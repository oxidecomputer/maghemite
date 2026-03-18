// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test utilities and macros for use across multiple crates.

use crate::lock;
use slog::{Logger, error, info};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const DEFAULT_INTERVAL: u64 = 1;
pub const DEFAULT_ITERATIONS: u64 = 30;

// Note: get_test_db has been moved to rdb::test::get_test_db
// to break the circular dependency between mg-common and rdb.
// Tests should now use rdb::test::get_test_db directly.

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

#[macro_export]
macro_rules! prefix4 {
    ($x:expr) => {
        parse!($x, "ipv4 prefix")
    };
}

#[macro_export]
macro_rules! prefix6 {
    ($x:expr) => {
        parse!($x, "ipv6 prefix")
    };
}

struct ManagedIp {
    address: IpAddr,
    /// Number of IpAllocations within this process currently using this IP.
    /// The system-level install/uninstall only happens when this transitions
    /// between 0 and 1. use_count > 0 implies the IP is installed.
    use_count: u32,
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

    fn add(&mut self, addresses: &[IpAddr]) {
        for addr in addresses {
            // Only add if not already present
            if !self.ips.iter().any(|ip| ip.address == *addr) {
                self.ips.push(ManagedIp {
                    address: *addr,
                    use_count: 0,
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
            if let Err(e) = mgr.install(addresses) {
                mgr.uninstall_addresses(addresses);
                return Err(e);
            }
        }

        // Return guard that will clean up on drop
        Ok(IpAllocation {
            addresses: addresses.to_vec(),
            manager,
        })
    }
}

/// Returns true for addresses that are always present on loopback interfaces
/// and should never be installed or removed by the manager.
fn is_always_present(addr: IpAddr) -> bool {
    addr == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || addr == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
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
    fn install(
        &mut self,
        addresses: &[IpAddr],
    ) -> Result<(), std::io::Error> {
        let ifname = self.ifname.clone();
        let log = self.log.clone();

        for ip in &mut self.ips {
            if addresses.contains(&ip.address) {
                Self::install_single_ip_static(&ifname, &log, ip)?;
            }
        }
        Ok(())
    }

    /// Install a single IP address with proper refcount management
    /// Skips 127.0.0.1/::1 as they're always present on loopback interfaces
    fn install_single_ip_static(
        ifname: &str,
        log: &Logger,
        ip: &mut ManagedIp,
    ) -> Result<(), std::io::Error> {
        if is_always_present(ip.address) {
            info!(log, "skipping {} (always present on loopback)", ip.address);
            ip.use_count += 1;
            return Ok(());
        }

        // If already installed by another allocation in this process, nothing
        // more to do — the system IP and lockfile refcount are already set up.
        // Increment use_count now since this path can't fail.
        if ip.use_count > 0 {
            ip.use_count += 1;
            info!(
                log,
                "{}: already installed, use_count now {}",
                ip.address,
                ip.use_count,
            );
            return Ok(());
        }

        // First use in this process: acquire the cross-process lockfile and
        // install the IP if no other process has done so yet.
        // Don't increment use_count until all fallible work succeeds.

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

        // 5. All fallible work done — update our state
        ip.use_count += 1;
        ip.lockfile = Some(lockfile);

        Ok(())
    }

    /// Add IP to the system using platform-specific commands
    fn add_ip_to_system(
        ifname: &str,
        log: &Logger,
        ip: &ManagedIp,
    ) -> Result<(), std::io::Error> {
        let mask = match ip.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let addr_str = format!("{}/{mask}", ip.address);

        #[cfg(target_os = "illumos")]
        let output = {
            let v = match ip.address {
                IpAddr::V4(_) => "v4",
                IpAddr::V6(_) => "v6",
            };
            let mut ip_descr = format!("{v}{}", ip.address);
            ip_descr.retain(|c| c.is_alphanumeric());
            let addr_obj = format!("{}/{}", ifname, ip_descr);
            let cmd = [
                "ipadm",
                "create-addr",
                "-t",
                "-T",
                "static",
                "-a",
                &addr_str,
                &addr_obj,
            ];
            info!(log, "running cmd '{cmd:?}'");
            Command::new("pfexec").args(cmd).output()?
        };

        #[cfg(target_os = "linux")]
        let output = Command::new("sudo")
            .args(["ip", "addr", "add", &addr_str, "dev", ifname])
            .output()?;

        #[cfg(target_os = "macos")]
        let output = {
            let af = match ip.address {
                IpAddr::V4(_) => "inet",
                IpAddr::V6(_) => "inet6",
            };
            Command::new("sudo")
                .args(["ifconfig", ifname, af, &addr_str, "alias"])
                .output()?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "Address already exists/assigned" is ok - another process beat us to it
            if !stderr.to_lowercase().contains("already") {
                error!(log, "failed to install {}: {stderr}", ip.address);
                return Err(std::io::Error::other(format!(
                    "failed to install {}",
                    ip.address
                )));
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

    /// Uninstall a single IP address with proper refcount management
    /// Skips 127.0.0.1 as it should always remain on loopback interfaces
    fn uninstall_single_ip(&mut self, target_addr: IpAddr) {
        if is_always_present(target_addr) {
            info!(
                self.log,
                "skipping {target_addr} cleanup (always present on loopback)"
            );
            for ip in &mut self.ips {
                if ip.address == target_addr {
                    ip.use_count = ip.use_count.saturating_sub(1);
                    break;
                }
            }
            return;
        }

        for ip in &mut self.ips {
            if ip.address == target_addr && ip.use_count > 0 {
                ip.use_count -= 1;

                if ip.use_count > 0 {
                    // Other allocations in this process still need this IP.
                    info!(
                        self.log,
                        "{}: use_count now {}, keeping installed",
                        ip.address,
                        ip.use_count,
                    );
                    break;
                }

                // Last in-process user: decrement the cross-process refcount
                // and remove the IP from the system if no other process needs it.
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
                            ip.address,
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

                info!(self.log, "uninstalled {}", ip.address);
                break;
            }
        }
    }

    /// Remove IP from the system using platform-specific commands
    fn remove_ip_from_system_static(ifname: &str, log: &Logger, addr: IpAddr) {
        #[cfg(target_os = "illumos")]
        let output = {
            let v = match addr {
                IpAddr::V4(_) => "v4",
                IpAddr::V6(_) => "v6",
            };
            let mut ip_descr = format!("{v}{addr}");
            ip_descr.retain(|c| c.is_alphanumeric());
            let addr_obj = format!("{ifname}/{ip_descr}");
            Command::new("pfexec")
                .args(["ipadm", "delete-addr", &addr_obj])
                .output()
        };

        #[cfg(target_os = "linux")]
        let output = {
            let mask = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let addr_str = format!("{addr}/{mask}");
            Command::new("sudo")
                .args(["ip", "addr", "del", &addr_str, "dev", ifname])
                .output()
        };

        #[cfg(target_os = "macos")]
        let output = {
            let af = match addr {
                IpAddr::V4(_) => "inet",
                IpAddr::V6(_) => "inet6",
            };
            Command::new("sudo")
                .args(["ifconfig", ifname, af, &addr.to_string(), "-alias"])
                .output()
        };

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
                            "failed to remove {addr} from system: {stderr}"
                        );
                        return;
                    }
                }
                info!(log, "removed {addr} from system");
            }
            Err(e) => {
                error!(
                    log,
                    "failed to execute remove command for {addr}: {e}"
                );
            }
        }
    }
}

/// Get the current thread count for this process.
/// Used for regression testing thread leaks.
///
/// Returns the number of threads currently active in this process.
pub fn current_thread_count() -> Result<usize, std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        Ok(std::fs::read_dir("/proc/self/task")?.count())
    }

    #[cfg(target_os = "illumos")]
    {
        let pid = std::process::id();
        Ok(std::fs::read_dir(format!("/proc/{}/lwp", pid))?.count())
    }

    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id();
        let output = Command::new("ps")
            .args(["-M", "-p", &pid.to_string()])
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::other("ps command failed"));
        }

        // Parse output: skip header line and count remaining lines
        let count = String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .count();

        Ok(count)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "illumos",
        target_os = "macos"
    )))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Thread counting not implemented for this platform",
        ))
    }
}

/// Count threads with names matching a specific prefix.
/// This is useful for counting only application threads and ignoring dependency threads.
///
/// On Illumos: Reads /proc/{pid}/lwp/{lwpid}/lwpname for each LWP
/// On Linux: Reads /proc/{pid}/task/{tid}/comm for each thread
/// On macOS: Parses `sample` command output to extract thread names
pub fn count_threads_with_prefix(
    prefix: &str,
) -> Result<usize, std::io::Error> {
    let pid = std::process::id();

    #[cfg(target_os = "illumos")]
    {
        use std::fs;
        let lwp_dir = format!("/proc/{}/lwp", pid);
        let mut count = 0;

        for entry in fs::read_dir(lwp_dir)? {
            let entry = entry?;
            let lwpid = entry.file_name();
            let name_path = format!(
                "/proc/{}/lwp/{}/lwpname",
                pid,
                lwpid.to_string_lossy()
            );

            if let Ok(name) = fs::read_to_string(&name_path) {
                let name = name.trim();
                if name.starts_with(prefix) {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let task_dir = format!("/proc/{}/task", pid);
        let mut count = 0;

        for entry in fs::read_dir(task_dir)? {
            let entry = entry?;
            let tid = entry.file_name();
            let comm_path =
                format!("/proc/{}/task/{}/comm", pid, tid.to_string_lossy());

            if let Ok(name) = fs::read_to_string(&comm_path) {
                let name = name.trim();
                if name.starts_with(prefix) {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;

        // Use sample command to capture thread information
        let output = Command::new("sample")
            .args([&pid.to_string(), "1", "-file", "/dev/stdout"])
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "sample command failed: {:?}",
                output.status
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut count = 0;

        // Parse sample output looking for lines like: "576 Thread_18401665: sled-io-0"
        // Thread names appear after the colon
        for line in stdout.lines() {
            // Look for pattern: "<number> Thread_<id>: <name>"
            if let Some(thread_part) = line.split_whitespace().nth(1)
                && thread_part.starts_with("Thread_")
            {
                // Check if there's a colon indicating a named thread
                if let Some(colon_pos) = line.find(':') {
                    // Extract the name after the colon
                    let name = line[colon_pos + 1..].trim();
                    if name.starts_with(prefix) {
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    #[cfg(not(any(
        target_os = "illumos",
        target_os = "linux",
        target_os = "macos"
    )))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Thread name counting is not implemented for this platform",
        ))
    }
}

/// Dump detailed stack traces for all threads in the current process.
/// This is useful for debugging thread leaks by showing what each thread is doing.
///
/// Platform-specific implementations:
/// - Illumos: Uses `pstack <pid> | demangle`
/// - Linux: Uses `gdb` to attach and dump thread backtraces
/// - macOS: Uses `sample` command for 1 second capture
pub fn dump_thread_stacks() -> Result<String, std::io::Error> {
    use std::process::Command;

    let pid = std::process::id();

    #[cfg(target_os = "illumos")]
    {
        // Use shell pipeline to run pstack and pipe through demangle
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("pstack {} | demangle", pid))
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "pstack | demangle failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[cfg(target_os = "linux")]
    {
        // Use gdb to attach and dump thread backtraces
        let output = Command::new("gdb")
            .args(&[
                "-batch",
                "-ex",
                "thread apply all bt",
                "-p",
                &pid.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "gdb failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[cfg(target_os = "macos")]
    {
        // Use sample command to capture thread stacks
        let output = Command::new("sample")
            .args([
                &pid.to_string(),
                "1", // Sample for 1 second
                "-file",
                "/dev/stdout",
            ])
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "sample failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[cfg(not(any(
        target_os = "illumos",
        target_os = "linux",
        target_os = "macos"
    )))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Thread stack dumping is not implemented for this platform",
        ))
    }
}
