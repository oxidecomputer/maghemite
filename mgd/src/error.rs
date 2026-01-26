// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::unnumbered_manager::{AddNeighborError, ResolveNeighborError};
use dropshot::{ClientErrorStatusCode, HttpError};

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

    #[error("error adding an unnumbered error: {0}")]
    AddUnnumberedNeighbor(#[from] AddNeighborError),

    #[error("error resolving a neighbor: {0}")]
    ResolveNeighbor(#[from] ResolveNeighborError),

    #[error("internal communication error: {0}")]
    InternalCommunication(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl From<Error> for HttpError {
    fn from(value: Error) -> Self {
        match value {
            Error::Db(_) => Self::for_internal_error(value.to_string()),
            Error::Conflict(_) => Self::for_client_error_with_status(
                Some(value.to_string()),
                ClientErrorStatusCode::CONFLICT,
            ),
            Error::NotFound(_) => Self::for_not_found(None, value.to_string()),
            Error::Bgp(ref err) => match err {
                bgp::error::Error::PeerExists => {
                    Self::for_client_error_with_status(
                        Some("bgp peer exists".into()),
                        ClientErrorStatusCode::CONFLICT,
                    )
                }
                _ => Self::for_internal_error(value.to_string()),
            },
            Error::AddUnnumberedNeighbor(ref err) => match err {
                AddNeighborError::Resolve(e) => match e {
                    ResolveNeighborError::NoSuchInterface
                    | ResolveNeighborError::NotIpv6Interface => {
                        Self::for_client_error_with_status(
                            Some(err.to_string()),
                            ClientErrorStatusCode::BAD_REQUEST,
                        )
                    }
                    ResolveNeighborError::System(e) => {
                        Self::for_internal_error(e.to_string())
                    }
                },
                AddNeighborError::NdpManager(e) => {
                    Self::for_internal_error(e.to_string())
                }
            },
            Error::ResolveNeighbor(ref err) => match err {
                ResolveNeighborError::NoSuchInterface
                | ResolveNeighborError::NotIpv6Interface => {
                    Self::for_client_error_with_status(
                        Some(err.to_string()),
                        ClientErrorStatusCode::BAD_REQUEST,
                    )
                }
                ResolveNeighborError::System(e) => {
                    Self::for_internal_error(e.to_string())
                }
            },
            Error::InternalCommunication(_) => {
                Self::for_internal_error(value.to_string())
            }
            Error::InvalidRequest(_) => {
                Self::for_bad_request(None, value.to_string())
            }
        }
    }
}
