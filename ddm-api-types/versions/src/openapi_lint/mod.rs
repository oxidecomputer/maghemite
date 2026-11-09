// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `OPENAPI_LINT` of the DDM Admin API.
//!
//! Makes the API pass openapi-lint: `PeerStatus` variants are serialized as
//! snake_case, and paths use kebab-case.

pub mod db;
