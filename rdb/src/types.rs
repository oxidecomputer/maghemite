use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Serialize, Deserialize)]
pub struct Route4Key {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
}

#[derive(Serialize, Deserialize)]
pub struct Route4MetricKey {
    pub route: Route4Key,
    pub metric: String,
}

#[derive(Serialize, Deserialize)]
pub struct Prefix4 {
    pub value: Ipv4Addr,
    pub length: u8,
}

#[derive(Serialize, Deserialize)]
pub struct Prefix6 {
    pub value: Ipv6Addr,
    pub length: u8,
}

#[derive(Serialize, Deserialize)]
pub struct BgpAttributes4 {
    pub origin: Ipv4Addr,
    pub path: Vec<Asn>,
}

#[derive(Serialize, Deserialize)]
pub struct BgpAttributes6 {
    pub origin: Ipv4Addr,
    pub path: Vec<Asn>,
}

#[derive(Serialize, Deserialize)]
pub enum Asn {
    TwoOctet(u16),
    FourOctet(u32),
}

#[derive(Serialize, Deserialize)]
pub enum Status {
    Up,
    Down,
}

pub fn to_buf<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(&value, &mut buf)?;
    Ok(buf)
}
