use rdb::Asn;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PeerConfig {
    pub name: String,
    pub host: SocketAddr,
    pub hold_time: u64,
    pub idle_hold_time: u64,
    pub delay_open: u64,
    pub connect_retry: u64,
    pub keepalive: u64,
    pub resolution: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct RouterConfig {
    pub asn: Asn,
    pub id: u32,
}
