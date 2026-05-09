// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! BGP-domain helpers that span all API versions.
//!
//! These submodules host BGP-area types whose lifetimes are *not* tied to a
//! particular wire version: parse-time error variants, RFC 7606 attribute
//! actions, and the `MessageConvertError` carrier. They are not part of any
//! published schema (decoder-internal `#[serde(skip)]` / `#[schemars(skip)]`
//! field embeds only) and so do not live under `vN/bgp/`.

pub mod error;
pub mod parse;
