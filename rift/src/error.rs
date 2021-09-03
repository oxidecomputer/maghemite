// Copyright 2021 Oxide Computer Company

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0} not implemented")]
    NotImplemented(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Platform error: {0}")]
    Platform(platform::error::Error),
}

impl From<platform::error::Error> for Error {
    fn from(e: platform::error::Error) -> Error { Error::Platform(e) }
}
