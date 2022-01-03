pub mod router;
pub mod mimos;
pub mod platform;
pub mod port;
pub mod config;
pub mod rdp;
pub mod protocol;
pub mod net;
pub mod admin;

#[macro_export]
macro_rules! router_error {
    ($log:expr, $router:expr, $format:expr) => {
        error!($log, "[{}]: {}", $router, $format)
    };
    ($log:expr, $router:expr, $error:expr, $format:expr) => {
        error!($log, "[{}]: {}: {}", $router, $format, $error)
    };
    ($log:expr, $router:expr, $error:expr, $format:expr, $($args:expr),*) => {
        error!($log, "[{}]: {}: {}", 
            $router, format!($format, $($args),*), $error)
    };
}

#[macro_export]
macro_rules! router_info {
    ($log:expr, $router:expr, $format:expr) => {
        info!($log, "[{}]: {}", $router, $format)
    };
    ($log:expr, $router:expr, $format:expr, $($args:expr),*) => {
        info!($log, "[{}]: {}", $router, format!($format, $($args),*))
    };
}

#[macro_export]
macro_rules! router_debug {
    ($log:expr, $router:expr, $format:expr) => {
        debug!($log, "[{}]: {}", $router, $format)
    };
    ($log:expr, $router:expr, $format:expr, $($args:expr),*) => {
        debug!($log, "[{}]: {}", $router, format!($format, $($args),*))
    };
}

#[macro_export]
macro_rules! router_trace {
    ($log:expr, $router:expr, $format:expr) => {
        trace!($log, "[{}]: {}", $router, $format)
    };
    ($log:expr, $router:expr, $format:expr, $($args:expr),*) => {
        trace!($log, "[{}]: {}", $router, format!($format, $($args),*))
    };
}

#[macro_export]
macro_rules! router_warn {
    ($log:expr, $router:expr, $format:expr) => {
        warn!($log, "[{}]: {}", $router, $format)
    };
    ($log:expr, $router:expr, $format:expr, $($args:expr),*) => {
        warn!($log, "[{}]: {}", $router, format!($format, $($args),*))
    };
}
