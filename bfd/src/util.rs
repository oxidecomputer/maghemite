use crate::{packet, PeerInfo};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[macro_export]
macro_rules! trc {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::trace!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::trace!(
            $self.log,
            "[{:?}][{}] {}",
            $self.state(),
            $self.peer,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! dbg {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::debug!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::debug!(
            $self.log,
            "[{:?}][{}] {}",
            $self.state(),
            $self.peer,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! inf {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::info!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::info!(
            $self.log,
            "[{:?}][{}] {}",
            $self.state(),
            $self.peer,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! wrn {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::warn!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::warn!(
            $self.log,
            "[{:?}][{}] {}",
            $self.state(),
            $self.peer,
            format!($($args)+)
        )
    };
}

#[macro_export]
macro_rules! err {
    ($log:expr, $state:expr, $peer:expr; $($args:tt)+) => {
        slog::error!(
            $log,
            "[{:?}][{}] {}",
            $state,
            $peer,
            format!($($args)+)
        )
    };
    ($self:ident; $($args:tt)+) => {
        slog::error!(
            $self.log,
            "[{:?}][{}] {}",
            $self.state(),
            $self.peer,
            format!($($args)+)
        )
    }
}

#[macro_export]
macro_rules! recv {
    ($self:ident, $endpoint:expr, $local:expr, $remote:expr) => {

        match $endpoint.rx.recv_timeout(
            $local.required_min_rx * $local.detection_multiplier.into()
        ) {
            Ok((addr, msg)) => {
                trc!($self; "recv: {:?}", msg);

                update_peer_info(&$remote, &msg);

                if msg.poll() {
                    $self.send_poll_response(
                        $self.peer,
                        $local,
                        $remote.clone(),
                        $endpoint.tx.clone(),
                        $self.log.clone(),
                    );
                }

                (addr, msg)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    wrn!($self; "timeout expired");
                    let next = Down::new($self.peer, $self.log.clone());
                    return Ok((Box::new(next), $endpoint));
            }
            Err(e) => {
                $crate::err!($self; "recv: {}, exiting recieve loop", e);
                return Err(anyhow::anyhow!("recv channel closed"));
            }
        }
    }
}

pub fn update_peer_info(remote: &Arc<Mutex<PeerInfo>>, msg: &packet::Control) {
    let mut r = remote.lock().unwrap();
    r.desired_min_tx = Duration::from_micros(msg.desired_min_tx.into());
    r.required_min_rx = Duration::from_micros(msg.required_min_rx.into());
    r.discriminator = msg.my_discriminator;
    r.demand_mode = msg.demand();
    r.detection_multiplier = msg.detect_mult;
}
