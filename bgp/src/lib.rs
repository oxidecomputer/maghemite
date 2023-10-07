pub mod clock;
pub mod config;
pub mod connection;
pub mod connection_tcp;
pub mod dispatcher;
pub mod error;
pub mod fanout;
pub mod log;
pub mod messages;
pub mod router;
pub mod session;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
mod test;

#[cfg(test)]
pub mod connection_channel;

pub const BGP_PORT: u16 = 179;

#[macro_export]
macro_rules! lock {
    ($mtx:expr) => {
        $mtx.lock().expect("lock mutex")
    };
}

#[macro_export]
macro_rules! read_lock {
    ($rwl:expr) => {
        $rwl.read().expect("rwlock read")
    };
}

#[macro_export]
macro_rules! write_lock {
    ($rwl:expr) => {
        $rwl.write().expect("rwlock write")
    };
}
