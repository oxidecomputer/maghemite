// Copyright 2021 Oxide Computer Company

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;

pub mod tie;
pub mod lie;

type SystemId = u64;
type LinkId = u32;
type TIENumber = u32;
type SequenceNumber = u64;
type Lifetime = u32; //seconds
type Metric = i32;
type InterfaceIndex = u32;
type OuterSecurityKeyId = u8;
type Bandwidth = u32; //mbps
type PodId = u32;
type Seconds = u64;
type IPv4Address = u32;
type IPv6Address = u128;
type PrefixLength = u8;
type RouteTag = u64;
type PrefixTransactionId = u8;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Header {
    pub major_version: MajorVersion,
    pub minor_version: u16,
    pub sender: SystemId,
    pub level: Level,
}

impl Default for Header {
    fn default() -> Header {
        Header {
            major_version: MajorVersion::V0,
            minor_version: MINOR_VERSION,
            sender: 0,
            level: Level::default(),
        }
    }
}


#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct NodeCapabilities {
    pub protocol_minor_version: u16,
    pub flood_reduction: Option<bool>,
    pub hierarchy_indication: Option<HierarchyIndication>,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LinkCapabilities {
    pub bfd: bool,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum HierarchyIndication {
    Leaf,
    ToF,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[repr(u8)]
pub enum MajorVersion {
    V0 = 0,
    V1 = 1,
}

const MINOR_VERSION: u16 = 1;

#[derive(
    Copy,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    JsonSchema,
    TryFromPrimitive,
    PartialEq,
    PartialOrd)]
#[repr(u8)]
pub enum Level {
    Leaf = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L5 = 5,
    L6 = 6,
    L7 = 7,
    L8 = 8,
    L9 = 9,
    L10 = 10,
    L11 = 11,
    L12 = 12,
    L13 = 13,
    L14 = 14,
    L15 = 15,
    L16 = 16,
    L17 = 17,
    L18 = 18,
    L19 = 19,
    L20 = 20,
    L21 = 21,
    L22 = 22,
    L23 = 23,
    TopOfFabric = 24,
}

impl Default for Level {
    fn default() -> Level {
        Level::Leaf
    }
}

impl std::str::FromStr for Level {

    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match u8::from_str(s) {
            Ok(i) => {
                match Level::try_from(i) {
                    Ok(l) => Ok(l),
                    Err(_) => Err("Level must be 0-24"),
                }
            }
            Err(_) => Err("Level must be integer")
        }
    }
}
