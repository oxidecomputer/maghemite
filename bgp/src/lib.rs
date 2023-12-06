use std::net::IpAddr;

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

//TODO use IpAddr::to_canonical once it stabilizes.
pub fn to_canonical(addr: IpAddr) -> IpAddr {
    match addr {
        v6 @ IpAddr::V6(ip) => match ip.to_ipv4() {
            Some(v4) => IpAddr::V4(v4),
            None => v6,
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}
