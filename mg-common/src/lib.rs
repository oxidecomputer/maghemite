// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cli;
pub mod log;
pub mod net;
pub mod nexus;
pub mod smf;
pub mod stats;
pub mod test;
pub mod thread;

use std::time::Duration;

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

/// Like `println!`, but silently exits on broken pipe (EPIPE) instead of
/// panicking. Other I/O errors still panic.
#[macro_export]
macro_rules! println_nopipe {
    () => {
        {
            use std::io::Write;
            let r = writeln!(std::io::stdout());
            match r {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => panic!("failed printing to stdout: {e}"),
            }
        }
    };
    ($($arg:tt)*) => {
        {
            use std::io::Write;
            let r = writeln!(std::io::stdout(), $($arg)*);
            match r {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => panic!("failed printing to stdout: {e}"),
            }
        }
    };
}

/// Like `print!`, but silently exits on broken pipe (EPIPE) instead of
/// panicking. Other I/O errors still panic.
#[macro_export]
macro_rules! print_nopipe {
    ($($arg:tt)*) => {
        {
            use std::io::Write;
            let r = write!(std::io::stdout(), $($arg)*);
            match r {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => panic!("failed printing to stdout: {e}"),
            }
        }
    };
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
