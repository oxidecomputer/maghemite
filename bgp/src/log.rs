#[macro_use]
pub mod session_runner {
    macro_rules! trc {
        ($self:ident, $unit:tt, $($args:tt)+) => {
            slog::trace!(
                $self.log,
                "[{}] {}",
                lock!($self.neighbor.name),
                format!($($args)+);
                "unit" => $unit
            )
        }
    }

    macro_rules! dbg {
        ($self:ident, $unit:tt, $($args:tt)+) => {
            slog::debug!(
                $self.log,
                "[{}] {}",
                lock!($self.neighbor.name),
                format!($($args)+);
                "unit" => $unit
            )
        }
    }

    macro_rules! inf {
        ($self:ident, $unit:tt, $($args:tt)+) => {
            slog::info!(
                $self.log,
                "[{}] {}",
                lock!($self.neighbor.name),
                format!($($args)+);
                "unit" => $unit
            )
        }
    }

    macro_rules! wrn {
        ($self:ident, $unit:tt, $($args:tt)+) => {
            slog::warn!(
                $self.log,
                "[{}] {}",
                lock!($self.neighbor.name),
                format!($($args)+);
                "unit" => $unit
            )
        }
    }

    macro_rules! err {
        ($self:ident, $unit:tt, $($args:tt)+) => {
            slog::error!(
                $self.log,
                "[{}] {}",
                lock!($self.neighbor.name),
                format!($($args)+);
                "unit" => $unit
            )
        }
    }

    pub(crate) use {dbg, err, inf, trc, wrn};
}
