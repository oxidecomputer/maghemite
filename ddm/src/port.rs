use std::cmp::Ordering;

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

#[derive(Debug, Copy, Clone, Deserialize, Serialize, JsonSchema, Eq, Hash, PartialEq)]
pub enum PortState {
    Unknown,
    Down,
    Up,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Port {
    pub index: usize,
    pub state: PortState,
}

impl Ord for Port {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index.cmp(&other.index)
    }
}

impl PartialOrd for Port {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.index.partial_cmp(&other.index)
    }
}
