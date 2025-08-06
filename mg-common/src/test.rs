// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Test utilities and macros for use across multiple crates.

#[macro_export]
macro_rules! wait_for_eq {
    ($lhs:expr, $rhs:expr, $period:expr, $count:expr) => {
        let mut ok = false;
        for _ in 0..$count {
            if $lhs == $rhs {
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs($period));
        }
        if !ok {
            assert_eq!($lhs, $rhs);
        }
    };
    ($lhs:expr, $rhs:expr) => {
        wait_for_eq!($lhs, $rhs, 1, 30);
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