// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::HttpError;
use http::StatusCode;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("database error {0}")]
    Db(#[from] rdb::error::Error),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bgp error: {0}")]
    Bgp(#[from] bgp::error::Error),

    #[error("internal communication error: {0}")]
    InternalCommunicationError(String),
}

impl From<Error> for HttpError {
    fn from(value: Error) -> Self {
        match value {
            Error::Db(_) => Self::for_internal_error(value.to_string()),
            Error::Conflict(_) => {
                Self::for_status(Some(value.to_string()), StatusCode::CONFLICT)
            }
            Error::NotFound(_) => Self::for_not_found(None, value.to_string()),
            Error::Bgp(ref err) => match err {
                bgp::error::Error::PeerExists => Self::for_status(
                    Some("bgp peer exists".into()),
                    StatusCode::CONFLICT,
                ),
                _ => Self::for_internal_error(value.to_string()),
            },
            Error::InternalCommunicationError(_) => {
                Self::for_internal_error(value.to_string())
            }
        }
    }
}
