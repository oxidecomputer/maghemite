// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

macro_rules! sm_log {
    ($log:ident, $level:ident, $msg:expr; $state:expr, $peer:expr, $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.current()),
            "peer" => format_args!("{}", $self.peer),
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $state:expr, $peer:expr, $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.current()),
            "peer" => format_args!("{}", $self.peer),
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr; $state:expr, $peer:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.current()),
            "peer" => format_args!("{}", $self.peer),
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $state:expr, $peer:expr) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.current()),
            "peer" => format_args!("{}", $self.peer),
        )
    };
}

macro_rules! state_log {
    ($log:ident, $level:ident, $msg:expr; $state:expr, $peer:expr, $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $state:expr, $peer:expr, $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
            $($key => $value),*
        )
    };
    ($log:ident, $level:ident, $msg:expr; $state:expr, $peer:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    };
    ($log:ident, $level:ident, $msg:expr, $($args:expr),*; $state:expr, $peer:expr) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $state),
            "peer" => format_args!("{}", $peer),
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BFD,
            "module" => crate::MOD_SM,
            "unit" => UNIT_SESSION,
            "state" => format_args!("{:?}", $self.state()),
            "peer" => format_args!("{}", $self.peer),
        )
    };
}

pub(crate) use {sm_log, state_log};
