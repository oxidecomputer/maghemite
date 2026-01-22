// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

macro_rules! session_log {
    ($self:expr, $level:ident, $conn:expr, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "connection" => format!("{:?}", $conn.conn()),
            "connection_id" => $conn.id().short(),
            "connection_clock" => format!("{}", $conn.clock()),
            "direction" => $conn.direction().as_str(),
            "fsm_state" => $self.state().as_str(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $conn:expr, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "connection" => format!("{:?}", $conn.conn()),
            "connection_id" => $conn.id().short(),
            "connection_clock" => format!("{}", $conn.clock()),
            "direction" => $conn.direction().as_str(),
            "fsm_state" => $self.state().as_str(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $conn:expr, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "connection" => format!("{:?}", $conn.conn()),
            "connection_id" => $conn.id().short(),
            "connection_clock" => format!("{}", $conn.clock()),
            "direction" => $conn.direction().as_str(),
            "fsm_state" => $self.state().as_str(),
        )
    };
    ($self:expr, $level:ident, $conn:expr, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "connection" => format!("{:?}", $conn.conn()),
            "connection_id" => $conn.id().short(),
            "connection_clock" => format!("{}", $conn.clock()),
            "direction" => $conn.direction().as_str(),
            "fsm_state" => $self.state().as_str(),
        )
    };
}

// session_log variant used in functions that don't have a BgpConnection
macro_rules! session_log_lite {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "fsm_state" => $self.state().as_str(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "fsm_state" => $self.state().as_str(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "fsm_state" => $self.state().as_str(),
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "fsm_state" => $self.state().as_str(),
        )
    };
}

macro_rules! collision_log {
    ($self:expr, $level:ident, $new:expr, $exist:expr, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "fsm_state" => $self.state().as_str(),
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "new_conn" => format!("{:?}", $new.conn()),
            "new_conn_id" => $new.id().short(),
            "new_connection_clock" => format!("{}", $new.clock()),
            "new_direction" => $new.direction().as_str(),
            "exist_conn" => format!("{:?}", $exist.conn()),
            "exist_conn_id" => $exist.id().short(),
            "exist_connection_clock" => format!("{}", $exist.clock()),
            "exist_direction" => $exist.direction().as_str(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $new:expr, $exist:expr, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "fsm_state" => $self.state().as_str(),
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "new_conn" => format!("{:?}", $new.conn()),
            "new_conn_id" => $new.id().short(),
            "new_connection_clock" => format!("{}", $new.clock()),
            "new_direction" => $new.direction().as_str(),
            "exist_conn" => format!("{:?}", $exist.conn()),
            "exist_conn_id" => $exist.id().short(),
            "exist_connection_clock" => format!("{}", $exist.clock()),
            "exist_direction" => $exist.direction().as_str(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $new:expr, $exist:expr, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "fsm_state" => $self.state().as_str(),
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "new_conn" => format!("{:?}", $new.conn()),
            "new_conn_id" => $new.id().short(),
            "new_connection_clock" => format!("{}", $new.clock()),
            "new_direction" => $new.direction().as_str(),
            "exist_conn" => format!("{:?}", $exist.conn()),
            "exist_conn_id" => $exist.id().short(),
            "exist_connection_clock" => format!("{}", $exist.clock()),
            "exist_direction" => $exist.direction().as_str(),
        )
    };
    ($self:expr, $level:ident, $new:expr, $exist:expr, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "fsm_state" => $self.state().as_str(),
            "neighbor_name" => lock!($self.neighbor.name).as_str(),
            "neighbor" => format!("{}", $self.neighbor.peer),
            "session_clock" => format!("{}", $self.clock),
            "new_conn" => format!("{:?}", $new.conn()),
            "new_conn_id" => $new.id().short(),
            "new_connection_clock" => format!("{}", $new.clock()),
            "new_direction" => $new.direction().as_str(),
            "exist_conn" => format!("{:?}", $exist.conn()),
            "exist_conn_id" => $exist.id().short(),
            "exist_connection_clock" => format!("{}", $exist.clock()),
            "exist_direction" => $exist.direction().as_str(),
        )
    };
}

macro_rules! dispatcher_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_DISPATCHER,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_DISPATCHER,
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_DISPATCHER,
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_DISPATCHER,
        )
    };
}

#[allow(unused_macros)]
macro_rules! connection_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "direction" => $self.direction().as_str(),
            "connection_id" => $self.id().short(),
            "connection_peer" => $self.peer(),
            "connection_local" => $self.local(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "direction" => $self.direction().as_str(),
            "connection_id" => $self.id().short(),
            "connection_peer" => $self.peer(),
            "connection_local" => $self.local(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "direction" => $self.direction().as_str(),
            "connection_id" => $self.id().short(),
            "connection_peer" => $self.peer(),
            "connection_local" => $self.local(),
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "direction" => $self.direction().as_str(),
            "connection_id" => $self.id().short(),
            "connection_peer" => $self.peer(),
            "connection_local" => $self.local(),
        )
    };
}

// connection_log variant used in functions that are not methods (no "self")
macro_rules! connection_log_lite {
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
        )
    };
}

#[allow(unused_imports)]
pub(crate) use {
    collision_log, connection_log, connection_log_lite, dispatcher_log,
    session_log, session_log_lite,
};
