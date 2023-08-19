use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Route4Key {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
}

impl ToString for Route4Key {
    fn to_string(&self) -> String {
        format!(
            "{}/{}/{}",
            self.nexthop, self.prefix.value, self.prefix.length,
        )
    }
}

impl Route4Key {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

pub struct Route4MetricKey {
    pub route: Route4Key,
    pub metric: String,
}

impl ToString for Route4MetricKey {
    fn to_string(&self) -> String {
        format!("{}/{}", self.route.to_string(), self.metric,)
    }
}

impl Route4MetricKey {
    pub fn db_key(&self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
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
