// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Persistence encoding for the latest MRIB route key types.
//!
//! Inherent impls must live in the crate that defines the type, but
//! behavior beyond version conversions stays out of the frozen version
//! modules. These impls target `latest`, following new versions automatically.

use crate::latest::mrib::{MulticastError, MulticastRouteKey};

impl MulticastRouteKey {
    /// Serialize this key to bytes for use as a sled database key.
    pub fn db_key(&self) -> Result<Vec<u8>, MulticastError> {
        let s = serde_json::to_string(self).map_err(|e| {
            MulticastError::Parsing(format!(
                "failed to serialize multicast route key: {e}"
            ))
        })?;
        Ok(s.as_bytes().into())
    }

    /// Deserialize a key from sled database bytes.
    pub fn from_db_key(v: &[u8]) -> Result<Self, MulticastError> {
        let s = String::from_utf8_lossy(v);
        serde_json::from_str(&s).map_err(|e| {
            MulticastError::DbKey(format!(
                "failed to parse multicast route key: {e}"
            ))
        })
    }
}
