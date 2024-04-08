// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::connection::BgpConnection;
use crate::session::FsmEvent;
use mg_common::lock;
use slog::{error, Logger};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;

#[derive(Clone)]
pub struct Clock {
    pub resolution: Duration,
    pub timers: Arc<ClockTimers>,
    pub join_handle: Arc<JoinHandle<()>>,

    shutdown: Arc<AtomicBool>,
}

pub struct ClockTimers {
    /// How long to wait between connection attempts.
    pub connect_retry_timer: Timer,

    /// Configured keepliave timer interval. May be distinct from actual
    /// keepalive interval depending on session parameter negotiation.
    pub keepalive_configured_interval: Duration,

    /// Time between sending keepalive messages.
    pub keepalive_timer: Mutex<Timer>,

    /// Configured hold timer interval. May be distinct from actual keepalive
    /// interval depending on session parameter negotiation.
    pub hold_configured_interval: Duration,

    /// How long to keep a session alive between keepalive, update and/or
    /// notification messages.
    pub hold_timer: Mutex<Timer>,

    /// Amount of time that a peer is held in the idle state.
    pub idle_hold_timer: Timer,

    /// Interval to wait before sending out an open message.
    pub delay_open_timer: Timer,
}

impl Clock {
    #[allow(clippy::too_many_arguments)]
    pub fn new<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        connect_retry_interval: Duration,
        keepalive_interval: Duration,
        hold_interval: Duration,
        idle_hold_interval: Duration,
        delay_open_interval: Duration,
        s: Sender<FsmEvent<Cnx>>,
        log: Logger,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let timers = Arc::new(ClockTimers {
            connect_retry_timer: Timer::new(connect_retry_interval),
            keepalive_configured_interval: keepalive_interval,
            keepalive_timer: Mutex::new(Timer::new(keepalive_interval)),
            hold_configured_interval: hold_interval,
            hold_timer: Mutex::new(Timer::new(hold_interval)),
            idle_hold_timer: Timer::new(idle_hold_interval),
            delay_open_timer: Timer::new(delay_open_interval),
        });
        let join_handle = Arc::new(Self::run(
            resolution,
            timers.clone(),
            s,
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
        timers: Arc<ClockTimers>,
        s: Sender<FsmEvent<Cnx>>,
        shutdown: Arc<AtomicBool>,
        log: Logger,
    ) -> JoinHandle<()> {
        spawn(move || loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            Self::step_all(resolution, timers.clone(), s.clone(), log.clone());
            sleep(resolution);
        })
    }

    fn step_all<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<ClockTimers>,
        s: Sender<FsmEvent<Cnx>>,
        log: Logger,
    ) {
        Self::step(
            resolution,
            &timers.connect_retry_timer,
            FsmEvent::ConnectRetryTimerExpires,
            s.clone(),
            &log,
        );
        Self::step(
            resolution,
            &timers.keepalive_timer.lock().unwrap(),
            FsmEvent::KeepaliveTimerExpires,
            s.clone(),
            &log,
        );
        Self::step(
            resolution,
            &timers.hold_timer.lock().unwrap(),
            FsmEvent::HoldTimerExpires,
            s.clone(),
            &log,
        );
        Self::step(
            resolution,
            &timers.idle_hold_timer,
            FsmEvent::IdleHoldTimerExpires,
            s.clone(),
            &log,
        );
        Self::step(
            resolution,
            &timers.delay_open_timer,
            FsmEvent::DelayOpenTimerExpires,
            s.clone(),
            &log,
        );
    }

    fn step<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        t: &Timer,
        event: FsmEvent<Cnx>,
        s: Sender<FsmEvent<Cnx>>,
        log: &Logger,
    ) {
        t.tick(resolution);
        if t.expired() {
            if let Err(e) = s.send(event.clone()) {
                error!(log, "send timer event {:?}: {e}", event);
            }
            t.reset();
        }
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct Timer {
    /// How long a timer runs until it fires.
    pub interval: Duration,

    /// Timer state. The first value indicates if the timer is enabled. The
    /// second value indicates how much time is left.
    value: Arc<Mutex<(bool, Duration)>>,
}

impl Timer {
    /// Create a new timer with the specified interval.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            value: Arc::new(Mutex::new((false, interval))),
        }
    }

    /// Make the timer tick, decrementing the value by the specified resolution.
    /// The decrementing actino is saturating, so ticking once the timer has
    /// reached zero is a no-op. Use `expred` to check for expiration.
    pub fn tick(&self, resolution: Duration) {
        let mut value = lock!(self.value);
        if value.0 {
            value.1 = value.1.saturating_sub(resolution);
        }
    }

    /// Returns true if the timer is enabled.
    pub fn enabled(&self) -> bool {
        lock!(self.value).0
    }

    /// Enable the timer. Only enabled timers can expire.
    pub fn enable(&self) {
        lock!(self.value).0 = true
    }

    /// Disable the timer. Only enabled timers can expire.
    pub fn disable(&self) {
        lock!(self.value).0 = false
    }

    /// Check if the timer has expired. Returns true if the timer is enabled and
    /// has ticked down to zero.
    pub fn expired(&self) -> bool {
        let v = lock!(self.value);
        v.0 && v.1.is_zero()
    }

    /// Reset the value of a timer to the timers interval.
    pub fn reset(&self) {
        lock!(self.value).1 = self.interval;
    }
}
