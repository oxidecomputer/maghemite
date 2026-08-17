// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(Box<libfalcon::error::Error>);

impl Error {
    /// Returns the underlying Falcon error.
    pub fn as_inner(&self) -> &libfalcon::error::Error {
        &self.0
    }

    /// Consumes this wrapper and returns the underlying Falcon error.
    pub fn into_inner(self) -> libfalcon::error::Error {
        *self.0
    }
}

impl From<libfalcon::error::Error> for Error {
    fn from(e: libfalcon::error::Error) -> Self {
        Error(Box::new(e))
    }
}
