// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::{BgpConnection, ConnectionId};
use crate::session::{ConnectionEvent, FsmEvent, SessionEvent};
use mg_common::lock;
use mg_common::thread::ManagedThread;
use slog::{Logger, error};
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, sleep, spawn};
use std::time::Duration;

const UNIT_TIMER: &str = "timer";

/// Timers for session-level events that persist across connections
#[derive(Debug)]
pub struct SessionTimers {
    /// How long to wait between connection attempts.
    pub connect_retry: Mutex<Timer>,
    /// Amount of time that a peer is held in the idle state.
    pub idle_hold: Mutex<Timer>,
}

/// Timers for connection-level events that are tied to individual connections
#[derive(Debug)]
pub struct ConnectionTimers {
    /// How long to keep a session alive between keepalive or update messages.
    /// The actual timer used for connection liveness detection is negotiated
    /// the BGP peer (shortest interval in either peer's Open wins).
    pub hold: Mutex<Timer>,
    /// The locally configured Hold Time for this peer
    pub config_hold_time: Duration,
    /// Time between sending keepalive messages. The actual timer used for
    /// triggering keepalives is negotiated with the BGP peer
    /// (negotiated hold timer / 3).
    pub keepalive: Mutex<Timer>,
    /// The locally configured Keepalive Time for this peer
    pub config_keepalive_time: Duration,
    /// Interval to wait before sending an open message.
    pub delay_open: Mutex<Timer>,
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

    /// Optional jitter range applied on restart. None = no jitter.
    /// Some((min, max)) applies a random factor in [min, max] to the interval.
    /// RFC 4271 recommends (0.75, 1.0) for ConnectRetryTimer and related timers.
    jitter_range: Option<(f64, f64)>,

    /// Timer state. The first value indicates if the timer is enabled. The
    /// second value indicates how much time is left.
    value: Arc<Mutex<TimerValue>>,
}

impl Timer {
    /// Create a new timer with the specified interval.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            jitter_range: None,
            value: Arc::new(Mutex::new(TimerValue {
                enabled: false,
                remaining: interval,
            })),
        }
    }

    /// Create a new timer with the specified interval and jitter range.
    /// The jitter_range parameter expects (min, max) where both values are
    /// factors to multiply the interval by. RFC 4271 recommends (0.75, 1.0) for
    /// ConnectRetryTimer and related timers.
    pub fn new_with_jitter(
        interval: Duration,
        jitter_range: (f64, f64),
    ) -> Self {
        Self {
            interval,
            jitter_range: Some(jitter_range),
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

    /// Reset the value of a timer to the timer's interval.
    /// If jitter is configured, a new random value within the jitter range
    /// is calculated and applied to the value each time this is called.
    /// The jitter is recalculated on every reset.
    pub fn reset(&self) {
        let interval = match self.jitter_range {
            Some((min, max)) => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let factor = rng.gen_range(min..=max);
                self.interval.mul_f64(factor)
            }
            None => self.interval,
        };
        lock!(self.value).remaining = interval;
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

    /// Update the jitter range for this timer. The new jitter will be applied
    /// on the next restart() call.
    pub fn set_jitter_range(&mut self, jitter_range: Option<(f64, f64)>) {
        self.jitter_range = jitter_range;
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
    /// The rate at which the clock ticks
    pub resolution: Duration,
    /// The collection of BGP timers specific to this SessionRunner
    pub timers: Arc<SessionTimers>,
    /// Handle to the thread running the per-session clock
    _thread: Arc<ManagedThread>,
}

impl SessionClock {
    pub fn new<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        connect_retry_interval: Duration,
        idle_hold_interval: Duration,
        connect_retry_jitter: Option<(f64, f64)>,
        idle_hold_jitter: Option<(f64, f64)>,
        event_tx: Sender<FsmEvent<Cnx>>,
        log: Logger,
    ) -> Self {
        let timers = Arc::new(SessionTimers {
            connect_retry: Mutex::new(match connect_retry_jitter {
                Some(jitter) => {
                    Timer::new_with_jitter(connect_retry_interval, jitter)
                }
                None => Timer::new(connect_retry_interval),
            }),
            idle_hold: Mutex::new(match idle_hold_jitter {
                Some(jitter) => {
                    Timer::new_with_jitter(idle_hold_interval, jitter)
                }
                None => Timer::new(idle_hold_interval),
            }),
        });
        let thread = Arc::new(ManagedThread::new());
        let _ = thread.start(Self::run(
            resolution,
            timers.clone(),
            event_tx,
            thread.dropped_flag(),
            log,
        ));
        Self {
            resolution,
            timers,
            _thread: thread,
        }
    }

    fn run<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<SessionTimers>,
        event_tx: Sender<FsmEvent<Cnx>>,
        dropped: Arc<AtomicBool>,
        log: Logger,
    ) -> JoinHandle<()> {
        spawn(move || {
            loop {
                if dropped.load(Ordering::Relaxed) {
                    break;
                }
                sleep(resolution);

                Self::step(
                    resolution,
                    &lock!(timers.connect_retry),
                    FsmEvent::Session(SessionEvent::ConnectRetryTimerExpires),
                    event_tx.clone(),
                    &log,
                );

                Self::step(
                    resolution,
                    &lock!(timers.idle_hold),
                    FsmEvent::Session(SessionEvent::IdleHoldTimerExpires),
                    event_tx.clone(),
                    &log,
                );
            }
        })
    }

    fn step<Cnx: BgpConnection + 'static>(
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
            // reset timer here so we don't fire an event for every tick
            timer.reset();
        }
    }

    pub fn stop_all(&self) {
        let timers = &self.timers;
        lock!(timers.connect_retry).stop();
        lock!(timers.idle_hold).stop();
    }
}

impl Display for SessionClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let connect_retry = lock!(self.timers.connect_retry);
        let idle_hold = lock!(self.timers.idle_hold);
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

/// Clock for connection-level timers tied to individual connections
#[derive(Clone, Debug)]
pub struct ConnectionClock {
    /// The rate at which the clock ticks
    pub resolution: Duration,
    /// The collection of BGP timers specific to this BgpConnection
    pub timers: Arc<ConnectionTimers>,
    /// The ID of the BgpConnection we're running a clock for
    pub conn_id: ConnectionId,
    /// Handle to the thread running the per-connection clock
    _thread: Arc<ManagedThread>,
}

impl ConnectionClock {
    #[allow(clippy::too_many_arguments)]
    pub fn new<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        keepalive_interval: Duration,
        hold_interval: Duration,
        delay_open_interval: Duration,
        conn_id: ConnectionId,
        event_tx: Sender<FsmEvent<Cnx>>,
        dropped: Arc<AtomicBool>,
        log: Logger,
    ) -> Self {
        let timers = Arc::new(ConnectionTimers {
            keepalive: Mutex::new(Timer::new(keepalive_interval)),
            hold: Mutex::new(Timer::new(hold_interval)),
            delay_open: Mutex::new(Timer::new(delay_open_interval)),
            config_hold_time: hold_interval,
            config_keepalive_time: keepalive_interval,
        });
        let thread = Arc::new(ManagedThread::new());
        thread.start(Self::run(
            resolution,
            timers.clone(),
            conn_id,
            event_tx,
            dropped.clone(),
            log,
        ));
        Self {
            resolution,
            timers,
            _thread: thread,
            conn_id,
        }
    }

    fn run<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<ConnectionTimers>,
        conn_id: ConnectionId,
        event_tx: Sender<FsmEvent<Cnx>>,
        dropped: Arc<AtomicBool>,
        log: Logger,
    ) -> JoinHandle<()> {
        spawn(move || {
            loop {
                if dropped.load(Ordering::Relaxed) {
                    break;
                }
                sleep(resolution);

                Self::step(
                    resolution,
                    &lock!(timers.keepalive),
                    FsmEvent::Connection(
                        ConnectionEvent::KeepaliveTimerExpires(conn_id),
                    ),
                    event_tx.clone(),
                    &log,
                );

                Self::step(
                    resolution,
                    &lock!(timers.hold),
                    FsmEvent::Connection(ConnectionEvent::HoldTimerExpires(
                        conn_id,
                    )),
                    event_tx.clone(),
                    &log,
                );

                Self::step(
                    resolution,
                    &lock!(timers.delay_open),
                    FsmEvent::Connection(
                        ConnectionEvent::DelayOpenTimerExpires(conn_id),
                    ),
                    event_tx.clone(),
                    &log,
                );
            }
        })
    }

    fn step<Cnx: BgpConnection + 'static>(
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
            // reset timer here so we don't fire an event for every tick
            timer.reset();
        }
    }

    pub fn disable_all(&self) {
        let timers = &self.timers;
        lock!(timers.keepalive).disable();
        lock!(timers.hold).disable();
        lock!(timers.delay_open).disable();
    }
}

impl Display for ConnectionClock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let keepalive = lock!(self.timers.keepalive);
        let hold = lock!(self.timers.hold);
        let delay_open = lock!(self.timers.delay_open);
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
