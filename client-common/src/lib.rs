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
