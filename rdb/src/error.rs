// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error {0}")]
    DataStore(#[from] sled::Error),

    #[error("data store transaction {0}")]
    DataStoreTransaction(#[from] sled::transaction::TransactionError),

    #[error("serialization error {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("db key error {0}")]
    DbKey(String),

    #[error("db value error {0}")]
    DbValue(String),

    #[error("Conflict {0}")]
    Conflict(String),

    #[error("Parsing error {0}")]
    Parsing(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<mg_api_types::mrib::MulticastError> for Error {
    fn from(value: mg_api_types::mrib::MulticastError) -> Self {
        match value {
            mg_api_types::mrib::MulticastError::Validation(s) => {
                Self::Validation(s)
            }
            mg_api_types::mrib::MulticastError::Parsing(s) => Self::Parsing(s),
            mg_api_types::mrib::MulticastError::DbKey(s) => Self::DbKey(s),
        }
    }
}
