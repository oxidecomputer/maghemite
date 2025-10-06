// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::{BgpConnection, ConnectionId};
use crate::session::{ConnectionEvent, FsmEvent, SessionEvent};
use crossbeam_channel::Sender;
use mg_common::lock;
use slog::{error, Logger};
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;

const UNIT_TIMER: &str = "timer";

/// Timers for session-level events that persist across connections
#[derive(Debug)]
pub struct SessionTimers {
    /// How long to wait between connection attempts.
    pub connect_retry_timer: Mutex<Timer>,
    /// Amount of time that a peer is held in the idle state.
    pub idle_hold_timer: Mutex<Timer>,
}

/// Timers for connection-level events that are tied to individual connections
#[derive(Debug)]
pub struct ConnectionTimers {
    /// How long to keep a session alive between keepalive or update messages.
    /// The actual timer used for connection liveness detection is negotiated
    /// the BGP peer (shortest interval in either peer's Open wins).
    pub hold_timer: Mutex<Timer>,
    /// The locally configured Hold Time for this peer
    pub config_hold_time: Duration,
    /// Time between sending keepalive messages. The actual timer used for
    /// triggering keepalives is negotiated with the BGP peer
    /// (negotiated hold timer / 3).
    pub keepalive_timer: Mutex<Timer>,
    /// The locally configured Keepalive Time for this peer
    pub config_keepalive_time: Duration,
    /// Interval to wait before sending an open message.
    pub delay_open_timer: Mutex<Timer>,
}

#[derive(Debug)]
pub struct TimerValue {
    enabled: bool,
    remaining: Duration,
}

impl Display for TimerValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "enabled: {}, remaining: {}.{:03}s",
            self.enabled,
            self.remaining.as_secs(),
            self.remaining.subsec_millis()
        )
    }
}

#[derive(Clone, Debug)]
pub struct Timer {
    /// How long a timer runs until it fires.
    pub interval: Duration,

    /// Timer state. The first value indicates if the timer is enabled. The
    /// second value indicates how much time is left.
    value: Arc<Mutex<TimerValue>>,
}

impl Timer {
    /// Create a new timer with the specified interval.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            value: Arc::new(Mutex::new(TimerValue {
                enabled: false,
                remaining: interval,
            })),
        }
    }

    /// Make the timer tick, decrementing the value by the specified resolution.
    /// The decrementing action is saturating, so ticking once the timer has
    /// reached zero is a no-op. Use `expired` to check for expiration.
    pub fn tick(&self, resolution: Duration) {
        let mut value = lock!(self.value);
        if value.enabled {
            value.remaining = value.remaining.saturating_sub(resolution);
        }
    }

    /// Returns true if the timer is enabled.
    pub fn enabled(&self) -> bool {
        lock!(self.value).enabled
    }

    /// Enable the timer. Only enabled timers can expire.
    pub fn enable(&self) {
        lock!(self.value).enabled = true
    }

    /// Disable the timer. Only enabled timers can expire.
    pub fn disable(&self) {
        lock!(self.value).enabled = false
    }

    /// Check if the timer has expired. Returns true if the timer is enabled and
    /// has ticked down to zero.
    pub fn expired(&self) -> bool {
        let v = lock!(self.value);
        v.enabled && v.remaining.is_zero()
    }

    /// Display time remaining on this timer
    pub fn remaining(&self) -> Duration {
        lock!(self.value).remaining
    }

    /// Reset the value of a timer to the timers interval.
    pub fn reset(&self) {
        lock!(self.value).remaining = self.interval;
    }

    /// Reset the timer to the interval and enable it.
    pub fn restart(&self) {
        self.reset();
        self.enable();
    }

    /// Disable and zero the timer.
    pub fn stop(&self) {
        self.disable();
        self.reset();
    }
}

impl Display for Timer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = lock!(self.value);
        write!(
            f,
            "Timer {{ interval: {}.{:03}s, {} }}",
            self.interval.as_secs(),
            self.interval.subsec_millis(),
            value
        )
    }
}

/// Clock for session-level timers that persist across connections
#[derive(Clone, Debug)]
pub struct SessionClock {
    pub resolution: Duration,
    pub timers: Arc<SessionTimers>,
    pub join_handle: Arc<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl SessionClock {
    pub fn new<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        connect_retry_interval: Duration,
        idle_hold_interval: Duration,
        event_tx: Sender<FsmEvent<Cnx>>,
        log: Logger,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let timers = Arc::new(SessionTimers {
            connect_retry_timer: Mutex::new(Timer::new(connect_retry_interval)),
            idle_hold_timer: Mutex::new(Timer::new(idle_hold_interval)),
        });
        let join_handle = Arc::new(Self::run(
            resolution,
            timers.clone(),
            event_tx,
            shutdown.clone(),
            log,
        ));
        Self {
            resolution,
            timers,
            join_handle,
            shutdown,
        }
    }

    fn run<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<SessionTimers>,
        event_tx: Sender<FsmEvent<Cnx>>,
        shutdown: Arc<AtomicBool>,
        log: Logger,
    ) -> JoinHandle<()> {
        spawn(move || loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            sleep(resolution);

            Self::check_timer(
                resolution,
                &lock!(timers.connect_retry_timer),
                FsmEvent::Session(SessionEvent::ConnectRetryTimerExpires),
                event_tx.clone(),
                &log,
            );

            Self::check_timer(
                resolution,
                &lock!(timers.idle_hold_timer),
                FsmEvent::Session(SessionEvent::IdleHoldTimerExpires),
                event_tx.clone(),
                &log,
            );
        })
    }

    fn check_timer<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timer: &Timer,
        event: FsmEvent<Cnx>,
        event_tx: Sender<FsmEvent<Cnx>>,
        log: &Logger,
    ) {
        timer.tick(resolution);
        if timer.expired() {
            if let Err(e) = event_tx.send(event) {
                error!(
                    log,
                    "{} send {:?} error: {e}",
                    UNIT_TIMER,
                    "session_timer_event"
                );
            }
        }
    }

    pub fn stop_all(&self) {
        let timers = &self.timers;
        lock!(timers.connect_retry_timer).stop();
        lock!(timers.idle_hold_timer).stop();
    }
}

impl Display for SessionClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let connect_retry = lock!(self.timers.connect_retry_timer);
        let idle_hold = lock!(self.timers.idle_hold_timer);
        write!(
            f,
            "SessionClock {{ resolution: {}.{:03}s, connect_retry: {}, idle_hold: {} }}",
            self.resolution.as_secs(),
            self.resolution.subsec_millis(),
            connect_retry,
            idle_hold
        )
    }
}

impl Drop for SessionClock {
    fn drop(&mut self) {
        // Only signal shutdown when this is the last clone being dropped.
        // Since all fields are Arc-wrapped and shared across clones, we check
        // if this is the final reference before stopping the clock thread.
        if Arc::strong_count(&self.shutdown) == 1 {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }
}

/// Clock for connection-level timers tied to individual connections
#[derive(Clone, Debug)]
pub struct ConnectionClock {
    pub resolution: Duration,
    pub timers: Arc<ConnectionTimers>,
    pub join_handle: Arc<JoinHandle<()>>,
    pub conn_id: ConnectionId,
    shutdown: Arc<AtomicBool>,
}

impl ConnectionClock {
    pub fn new<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        keepalive_interval: Duration,
        hold_interval: Duration,
        delay_open_interval: Duration,
        conn_id: ConnectionId,
        event_tx: Sender<FsmEvent<Cnx>>,
        log: Logger,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let timers = Arc::new(ConnectionTimers {
            keepalive_timer: Mutex::new(Timer::new(keepalive_interval)),
            hold_timer: Mutex::new(Timer::new(hold_interval)),
            delay_open_timer: Mutex::new(Timer::new(delay_open_interval)),
            config_hold_time: hold_interval,
            config_keepalive_time: keepalive_interval,
        });
        let join_handle = Arc::new(Self::run(
            resolution,
            timers.clone(),
            conn_id,
            event_tx,
            shutdown.clone(),
            log,
        ));
        Self {
            resolution,
            timers,
            join_handle,
            conn_id,
            shutdown,
        }
    }

    fn run<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<ConnectionTimers>,
        conn_id: ConnectionId,
        event_tx: Sender<FsmEvent<Cnx>>,
        shutdown: Arc<AtomicBool>,
        log: Logger,
    ) -> JoinHandle<()> {
        spawn(move || loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            sleep(resolution);

            Self::check_timer(
                resolution,
                &lock!(timers.keepalive_timer),
                FsmEvent::Connection(ConnectionEvent::KeepaliveTimerExpires(
                    conn_id,
                )),
                event_tx.clone(),
                &log,
            );

            Self::check_timer(
                resolution,
                &lock!(timers.hold_timer),
                FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(
                    conn_id,
                )),
                event_tx.clone(),
                &log,
            );

            Self::check_timer(
                resolution,
                &lock!(timers.delay_open_timer),
                FsmEvent::Connection(ConnectionEvent::DelayOpenTimerExpires(
                    conn_id,
                )),
                event_tx.clone(),
                &log,
            );
        })
    }

    fn check_timer<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timer: &Timer,
        event: FsmEvent<Cnx>,
        event_tx: Sender<FsmEvent<Cnx>>,
        log: &Logger,
    ) {
        timer.tick(resolution);
        if timer.expired() {
            if let Err(e) = event_tx.send(event) {
                error!(
                    log,
                    "{} send {:?} error: {e}",
                    UNIT_TIMER,
                    "connection_timer_event"
                );
            }
        }
    }

    pub fn disable_all(&self) {
        let timers = &self.timers;
        lock!(timers.keepalive_timer).disable();
        lock!(timers.hold_timer).disable();
        lock!(timers.delay_open_timer).disable();
    }
}

impl Display for ConnectionClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let keepalive = lock!(self.timers.keepalive_timer);
        let hold = lock!(self.timers.hold_timer);
        let delay_open = lock!(self.timers.delay_open_timer);
        write!(
            f,
            "ConnectionClock {{ conn_id: {}, resolution: {}.{:03}s, keepalive: {}, hold: {}, delay_open: {} }}",
            self.conn_id.short(),
            self.resolution.as_secs(),
            self.resolution.subsec_millis(),
            keepalive,
            hold,
            delay_open
        )
    }
}

impl Drop for ConnectionClock {
    fn drop(&mut self) {
        // Only signal shutdown when this is the last clone being dropped.
        // Since all fields are Arc-wrapped and shared across clones, we check
        // if this is the final reference before stopping the clock thread.
        if Arc::strong_count(&self.shutdown) == 1 {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }
}
