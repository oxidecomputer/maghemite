// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! v11 (NDP_NO_ASN): the NDP admin endpoints are one-per-mgd-instance, so the
//! BGP ASN was dropped from their selectors. Only `NdpInterfaceSelector`
//! changed shape; the response types are unchanged and remain at v5.

pub mod ndp;
