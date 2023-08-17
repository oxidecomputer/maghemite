use crate::session::Asn;
use std::collections::HashSet;
use std::net::IpAddr; //TODO move this out of crate::session

#[derive(Default)]
pub struct BgpState {
    pub in_rib: Rib,
    pub local_rib: Rib,
    pub out_rib: Rib,
}

#[derive(Hash)]
pub struct RibEntry {
    origin: IpAddr,
    path: Vec<Asn>,
    nexthop: IpAddr,
}

#[derive(Hash)]
pub enum Prefix {
    V4(Vec<u8>),
    V6(Vec<u8>),
}

#[derive(Default)]
pub struct Rib {
    pub entries: HashSet<RibEntry>,
}
