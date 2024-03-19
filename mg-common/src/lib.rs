// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cli;
pub mod net;
pub mod nexus;
pub mod stats;

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

//
// stats macros
//

#[macro_export]
macro_rules! counter {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Default, Metric)]
        pub struct $name {
            #[datum]
            count: Cumulative<u64>,
        }
    };
}

#[macro_export]
macro_rules! quantity {
    ($name:ident, $kind:tt) => {
        #[derive(Clone, Copy, Debug, Default, Metric)]
        pub struct $name {
            #[datum]
            quantity: $kind,
        }
    };
}
