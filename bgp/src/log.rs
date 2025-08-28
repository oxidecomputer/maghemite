macro_rules! session_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_NEIGHBOR,
            "module" => MOD_SESSION,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "remote" => $self.neighbor.host,
            $($key => $value),*
        );
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_NEIGHBOR,
            "module" => MOD_SESSION,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "remote" => $self.neighbor.host,
            $($key => $value),*
        );
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_NEIGHBOR,
            "module" => MOD_SESSION,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "remote" => $self.neighbor.host,
        );
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_NEIGHBOR,
            "module" => MOD_SESSION,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "remote" => $self.neighbor.host,
        );
    };
}

macro_rules! dispatcher_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_LISTENER,
            "module" => MOD_DISPATCHER,
            $($key => $value),*
        );
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_LISTENER,
            "module" => MOD_DISPATCHER,
            $($key => $value),*
        );
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_LISTENER,
            "module" => MOD_DISPATCHER,
        );
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "unit" => crate::UNIT_LISTENER,
            "module" => MOD_DISPATCHER,
        );
    };
}

pub(crate) use {dispatcher_log, session_log};
