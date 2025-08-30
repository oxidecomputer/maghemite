macro_rules! session_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "peer_sockaddr" => $self.neighbor.host,
            "source" => format!("{:?}", $self.bind_addr),
            "clock" => format!("{:#?}", $self.clock),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "peer_sockaddr" => $self.neighbor.host,
            "source" => format!("{:?}", $self.bind_addr),
            "clock" => format!("{:#?}", $self.clock),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "peer_sockaddr" => $self.neighbor.host,
            "source" => format!("{:?}", $self.bind_addr),
            "clock" => format!("{:#?}", $self.clock),
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_SESSION_RUNNER,
            "peer_name" => lock!($self.neighbor.name).as_str(),
            "peer_sockaddr" => $self.neighbor.host,
            "source" => format!("{:?}", $self.bind_addr),
            "clock" => format!("{:#?}", $self.clock),
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

macro_rules! connection_log {
    ($self:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "creator" => &$self.creator,
            "peer" => $self.peer(),
            "source" => $self.local(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "creator" => &$self.creator,
            "peer" => $self.peer(),
            "source" => $self.local(),
            $($key => $value),*
        )
    };
    ($self:expr, $level:ident, $msg:expr) => {
        slog::$level!($self.log,
            $msg;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "creator" => &$self.creator,
            "peer" => $self.peer(),
            "source" => $self.local(),
        )
    };
    ($self:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($self.log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_BGP,
            "module" => crate::MOD_NEIGHBOR,
            "unit" => UNIT_CONNECTION,
            "creator" => &$self.creator,
            "peer" => $self.peer(),
            "source" => $self.local(),
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

pub(crate) use {
    connection_log, connection_log_lite, dispatcher_log, session_log,
};
