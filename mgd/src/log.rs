macro_rules! bfd_log {
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BFD,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BFD,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BFD
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BFD,
        )
    };
}

macro_rules! bgp_log {
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BGP,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BGP,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BGP
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_BGP,
        )
    };
}

// daemon
macro_rules! dlog {
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_DAEMON,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_DAEMON,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_DAEMON
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_DAEMON,
        )
    };
}

// oxstats
macro_rules! olog {
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_OXSTATS,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_OXSTATS,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_OXSTATS
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_OXSTATS,
        )
    };
}

macro_rules! smf_log {
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_SMF,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_SMF,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_SMF
        )
    };
    ($log:expr, $level:ident, $msg:expr, $($args:expr),*) => {
        slog::$level!($log,
            $msg, $($args),*;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_SMF,
        )
    };
}

macro_rules! sig_log {
    ($log:expr, $level:ident, $msg:expr; $($key:expr => $value:expr),*) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_SIG,
            $($key => $value),*
        )
    };
    ($log:expr, $level:ident, $msg:expr) => {
        slog::$level!($log,
            $msg;
            "component" => crate::COMPONENT_MGD,
            "module" => crate::MOD_ADMIN,
            "unit" => UNIT_SIG
        )
    };
}

pub(crate) use {bfd_log, bgp_log, dlog, olog, sig_log, smf_log};
