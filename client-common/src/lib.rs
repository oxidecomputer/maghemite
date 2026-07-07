// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

/// Like `eprintln!`, but silently exits on broken pipe (EPIPE) instead of
/// panicking. Other I/O errors still panic.
#[macro_export]
macro_rules! eprintln_nopipe {
    () => {
        {
            use std::io::Write;
            let r = writeln!(std::io::stderr());
            match r {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => panic!("failed printing to stderr: {e}"),
            }
        }
    };
    ($($arg:tt)*) => {
        {
            use std::io::Write;
            let r = writeln!(std::io::stderr(), $($arg)*);
            match r {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => panic!("failed printing to stderr: {e}"),
            }
        }
    };
}

/// Like `eprint!`, but silently exits on broken pipe (EPIPE) instead of
/// panicking. Other I/O errors still panic.
#[macro_export]
macro_rules! eprint_nopipe {
    ($($arg:tt)*) => {
        {
            use std::io::Write;
            let r = write!(std::io::stderr(), $($arg)*);
            match r {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    std::process::exit(0);
                },
                Err(e) => panic!("failed printing to stderr: {e}"),
            }
        }
    };
}

/// Format a Duration for human-readable display.
///
/// Examples: "426d 13h 24m 9s", "3h 12m 5s", "1m 30s 250ms", "500ms"
///
/// Leading zero units are omitted and milliseconds are dropped above 1 hour.
pub fn format_duration_human(d: std::time::Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    let millis = d.subsec_millis();

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {seconds}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s {millis}ms")
    } else if seconds > 0 {
        format!("{seconds}s {millis}ms")
    } else {
        format!("{millis}ms")
    }
}
