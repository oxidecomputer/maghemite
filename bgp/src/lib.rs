// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod clock;
pub mod config;
pub mod connection;
pub mod connection_tcp;
pub mod dispatcher;
pub mod error;
pub mod fanout;
pub mod log;
pub mod messages;
pub mod params;
pub mod policy;
pub mod router;
pub mod session;

mod rhai_integration;

#[cfg(test)]
mod proptest;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod test;

#[cfg(test)]
pub mod connection_channel;

pub const BGP_PORT: u16 = 179;
pub const COMPONENT_BGP: &str = "bgp";
pub const MOD_ROUTER: &str = "router";
pub const MOD_NEIGHBOR: &str = "neighbor";
pub const MOD_CLOCK: &str = "clock";
pub const MOD_POLICY: &str = "policy";

// XXX: Make this configurable
pub const IO_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(100);

/// Macro for receiving FSM events in loop-based FSM states.
///
/// This macro abstracts the common pattern of reading from `self.event_rx` with
/// automatic logging. On timeout or error, it continues the loop (retries).
///
/// # Examples
///
/// For methods without a connection context (using `session_log_lite!`):
/// ```ignore
/// let event = recv_event_loop!(self, event_rx, lite);
/// ```
///
/// For methods with a connection context (using `session_log!`):
/// ```ignore
/// let event = recv_event_loop!(self, event_rx, conn, pc.conn);
/// ```
///
/// For collision handlers (using `collision_log!`):
/// ```ignore
/// let event = recv_event_loop!(self, event_rx, collision, new, exist.conn);
/// ```
#[macro_export]
macro_rules! recv_event_loop {
    // Variant 1: session_log_lite! (no connection context)
    ($self:expr, $event_rx:expr, lite) => {
        match $event_rx.recv_timeout($crate::IO_TIMEOUT) {
            Ok(event) => {
                $crate::log::session_log_lite!(
                    $self,
                    debug,
                    "received fsm event {}",
                    event.title();
                    "event" => event.title()
                );
                event
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(e) => {
                $crate::log::session_log_lite!(
                    $self,
                    error,
                    "event rx error: {e}";
                    "error" => format!("{e}")
                );
                continue;
            }
        }
    };

    // Variant 2: session_log! (with connection context)
    ($self:expr, $event_rx:expr, conn, $conn:expr) => {
        match $event_rx.recv_timeout($crate::IO_TIMEOUT) {
            Ok(event) => {
                $crate::log::session_log!(
                    $self,
                    debug,
                    $conn,
                    "received fsm event";
                    "event" => event.title()
                );
                event
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(e) => {
                $crate::log::session_log!(
                    $self,
                    error,
                    $conn,
                    "event rx error: {e}";
                    "error" => format!("{e}")
                );
                continue;
            }
        }
    };

    // Variant 3: collision_log! (for collision handlers)
    ($self:expr, $event_rx:expr, collision, $new:expr, $exist:expr) => {
        match $event_rx.recv_timeout($crate::IO_TIMEOUT) {
            Ok(event) => {
                $crate::log::collision_log!(
                    $self,
                    debug,
                    $new,
                    $exist,
                    "received fsm event {}", event.title();
                    "event" => event.title()
                );
                event
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(e) => {
                $crate::log::collision_log!(
                    $self,
                    error,
                    $new,
                    $exist,
                    "event rx error: {e}";
                    "error" => format!("{e}")
                );
                continue;
            }
        }
    };
}

/// Macro for receiving FSM events in single-pass FSM states.
///
/// This macro abstracts the common pattern of reading from `self.event_rx` with
/// automatic logging. On timeout or error, it returns the provided state immediately.
///
/// # Examples
///
/// For methods that return a specific state:
/// ```ignore
/// let event = recv_event_return!(self, event_rx, FsmState::OpenConfirm(pc), pc.conn);
/// let event = recv_event_return!(self, event_rx, FsmState::Established(pc), pc.conn);
/// ```
#[macro_export]
macro_rules! recv_event_return {
    // Variant: session_log! (with connection context and return state)
    ($self:expr, $event_rx:expr, $return_state:expr, $conn:expr) => {
        match $event_rx.recv_timeout($crate::IO_TIMEOUT) {
            Ok(event) => {
                $crate::log::session_log!(
                    $self,
                    debug,
                    $conn,
                    "received fsm event";
                    "event" => event.title()
                );
                event
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return $return_state,
            Err(e) => {
                $crate::log::session_log!(
                    $self,
                    error,
                    $conn,
                    "event rx error: {e}";
                    "error" => format!("{e}")
                );
                return $return_state;
            }
        }
    };
}
