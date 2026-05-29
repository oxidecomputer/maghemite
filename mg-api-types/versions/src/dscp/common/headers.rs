// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// IP QoS value for IPv4 and IPv6 connections (0-63).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Dscp(pub(crate) u8);

impl TryFrom<u8> for Dscp {
    type Error = String;
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        if val > 63 {
            Err(format!("DSCP value {val} out of range (0-63)"))
        } else {
            Ok(Self(val))
        }
    }
}

impl From<Dscp> for u8 {
    fn from(d: Dscp) -> u8 {
        d.0
    }
}

impl JsonSchema for Dscp {
    fn schema_name() -> String {
        "Dscp".to_string()
    }
    fn json_schema(
        _g: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::Integer.into()),
            format: Some("uint8".to_string()),
            number: Some(Box::new(schemars::schema::NumberValidation {
                minimum: Some(0.0),
                maximum: Some(63.0),
                ..Default::default()
            })),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "DSCP value (0-63). Default: CS0 (0).".to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}
