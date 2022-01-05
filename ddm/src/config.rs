use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub struct Config {
    pub admin_port: u16,
}
