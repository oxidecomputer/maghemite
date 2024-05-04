// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error {0}")]
    DataStore(#[from] sled::Error),

    #[error("serialization error {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("db key error {0}")]
    DbKey(String),

    #[error("db value error {0}")]
    DbValue(String),

    #[error("Conflict {0}")]
    Conflict(String),
}
