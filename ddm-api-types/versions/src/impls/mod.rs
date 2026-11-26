// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trait impls and helpers on the versioned types.
//!
//! Keeping impls outside version modules avoids duplicate implementations
//! when later versions re-export the same types.

mod mcast;
