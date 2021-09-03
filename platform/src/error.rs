// Copyright 2021 Oxide Computer Company

use thiserror::Error;
use std::ffi::IntoStringError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0} not implemented")]
    NotImplemented(String),

    #[error("Platform error: {0}")]
    Platform(String),
}

impl From<IntoStringError> for Error {
    fn from(e: IntoStringError) -> Error { 
        Error::Platform(format!("into string: {}", e)) 
    }
}

