use crate::connection::BgpConnection;
use crate::session::FsmEvent;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;

#[derive(Clone)]
pub struct Clock {
    pub resolution: Duration,
    pub timers: Arc<ClockTimers>,
    pub join_handle: Arc<JoinHandle<()>>,
}

pub struct ClockTimers {
    /// How long to wait between connection attempts.
    pub connect_retry_timer: Timer,

    /// How often to send out keepalive messages.
    pub keepalive_timer: Timer,

    /// How long to keep a session alive between keepalive, update and/or
    /// notification messages.
    pub hold_timer: Timer,

    /// Amount of time that a peer is held in the idle state.
    pub idle_hold_timer: Timer,

    /// Interval to wait before sending out an open message.
    pub delay_open_timer: Timer,
}

impl Clock {
    pub fn new<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        connect_retry_interval: Duration,
        keepalive_interval: Duration,
        hold_interval: Duration,
        idle_hold_interval: Duration,
        delay_open_interval: Duration,
        s: Sender<FsmEvent<Cnx>>,
    ) -> Self {
        let timers = Arc::new(ClockTimers {
            connect_retry_timer: Timer::new(connect_retry_interval),
            keepalive_timer: Timer::new(keepalive_interval),
            hold_timer: Timer::new(hold_interval),
            idle_hold_timer: Timer::new(idle_hold_interval),
            delay_open_timer: Timer::new(delay_open_interval),
        });
        let join_handle = Arc::new(Self::run(resolution, timers.clone(), s));
        Self {
            resolution,
            timers,
            join_handle,
        }
    }

    fn run<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<ClockTimers>,
        s: Sender<FsmEvent<Cnx>>,
    ) -> JoinHandle<()> {
        spawn(move || loop {
            if Self::step_all(resolution, timers.clone(), s.clone()).is_err() {
                //TODO log
                break;
            }
        })
    }

    fn step_all<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        timers: Arc<ClockTimers>,
        s: Sender<FsmEvent<Cnx>>,
    ) -> anyhow::Result<()> {
        Self::step(
            resolution,
            &timers.connect_retry_timer,
            FsmEvent::ConnectRetryTimerExpires,
            s.clone(),
        )?;
        Self::step(
            resolution,
            &timers.keepalive_timer,
            FsmEvent::KeepaliveTimerExpires,
            s.clone(),
        )?;
        Self::step(
            resolution,
            &timers.hold_timer,
            FsmEvent::HoldTimerExpires,
            s.clone(),
        )?;
        Self::step(
            resolution,
            &timers.idle_hold_timer,
            FsmEvent::IdleHoldTimerExpires,
            s.clone(),
        )?;
        Self::step(
            resolution,
            &timers.delay_open_timer,
            FsmEvent::DelayOpenTimerExpires,
            s.clone(),
        )?;
        sleep(resolution);
        Ok(())
    }

    fn step<Cnx: BgpConnection + 'static>(
        resolution: Duration,
        t: &Timer,
        e: FsmEvent<Cnx>,
        s: Sender<FsmEvent<Cnx>>,
    ) -> anyhow::Result<()> {
        t.tick(resolution);
        if t.expired() {
            s.send(e).map_err(|_| anyhow::anyhow!("timer send"))?;
            t.reset();
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Timer {
    pub interval: Duration,
    pub value: Arc<Mutex<(bool, Duration)>>,
}

impl Timer {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            value: Arc::new(Mutex::new((false, interval))),
        }
    }

    pub fn tick(&self, resolution: Duration) {
        let mut value = self.value.lock().unwrap();
        if value.0 {
            value.1 = value.1.saturating_sub(resolution);
        }
    }

    pub fn enabled(&self) -> bool {
        self.value.lock().unwrap().0
    }

    pub fn enable(&self) {
        self.value.lock().unwrap().0 = true
    }

    pub fn disable(&self) {
        self.value.lock().unwrap().0 = false
    }

    pub fn expired(&self) -> bool {
        let v = self.value.lock().unwrap();
        v.0 && v.1.is_zero()
    }

    pub fn reset(&self) {
        self.value.lock().unwrap().1 = self.interval;
    }
}
