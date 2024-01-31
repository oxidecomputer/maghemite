// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::mpsc::{self, Receiver, Sender};

/// A combined mpsc sender/receiver.
pub struct Endpoint<T> {
    pub rx: Receiver<T>,
    pub tx: Sender<T>,
}

impl<T> Endpoint<T> {
    fn new(rx: Receiver<T>, tx: Sender<T>) -> Self {
        Self { rx, tx }
    }
}

/// Analogous to std::sync::mpsc::channel for bidirectional endpoints.
pub fn channel<T>() -> (Endpoint<T>, Endpoint<T>) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (Endpoint::new(rx_a, tx_a), Endpoint::new(rx_b, tx_b))
}
