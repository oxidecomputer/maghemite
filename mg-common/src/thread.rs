// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Thread management utilities for consistent lifecycle handling.

use crate::lock;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

/// Status of a managed child thread.
#[derive(Debug)]
pub enum ThreadState {
    /// Thread has not been started yet
    Ready,
    /// Thread is running with the given handle
    Running(JoinHandle<()>),
}

impl ThreadState {
    /// Create a new thread state in the Ready state
    pub fn new() -> Self {
        ThreadState::Ready
    }

    /// Check if the thread is ready to start
    pub fn is_ready(&self) -> bool {
        matches!(self, ThreadState::Ready)
    }

    /// Check if the thread is currently running
    pub fn is_running(&self) -> bool {
        matches!(self, ThreadState::Running(_))
    }

    /// Transition from Ready to Running with the given handle.
    pub fn start(&mut self, handle: JoinHandle<()>) {
        if self.is_ready() {
            *self = ThreadState::Running(handle);
        }
    }
}

impl Default for ThreadState {
    fn default() -> Self {
        Self::new()
    }
}

/// A managed thread that handles shutdown signaling and cleanup automatically.
/// This type bundles together a thread's JoinHandle with its shutdown signal
/// flag, ensuring consistent lifecycle management across all thread types.
///
/// The ManagedThread is intentionally NOT Clone - it should only be wrapped in
/// Arc to ensure Drop runs exactly once when all references are released.
#[derive(Debug)]
pub struct ManagedThread {
    state: Mutex<ThreadState>,
    dropped: Arc<AtomicBool>,
}

impl ManagedThread {
    /// Create a new managed thread in the Ready state
    pub fn new() -> Self {
        ManagedThread {
            state: Mutex::new(ThreadState::Ready),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the managed thread with the given handle.
    /// Returns a clone of the dropped flag that the thread should check periodically.
    pub fn start(&self, handle: JoinHandle<()>) -> Arc<AtomicBool> {
        let mut state = lock!(self.state);
        state.start(handle);
        self.dropped.clone()
    }

    /// Get a clone of the dropped flag for checking shutdown state
    pub fn dropped_flag(&self) -> Arc<AtomicBool> {
        self.dropped.clone()
    }

    /// Check if the thread is ready to start
    pub fn is_ready(&self) -> bool {
        lock!(self.state).is_ready()
    }

    /// Check if the thread is currently running
    pub fn is_running(&self) -> bool {
        lock!(self.state).is_running()
    }
}

impl Drop for ManagedThread {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Relaxed);

        let mut state = lock!(self.state);
        if let ThreadState::Running(handle) =
            std::mem::replace(&mut *state, ThreadState::Ready)
        {
            drop(state);
            let _ = handle.join();
        }
    }
}

impl Default for ManagedThread {
    fn default() -> Self {
        Self::new()
    }
}
