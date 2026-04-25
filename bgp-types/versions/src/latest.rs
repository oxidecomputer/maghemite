// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Re-exports of the latest versions of types.

pub mod messages {
    pub use crate::v1::messages::{
        AsPathType, CapabilityCode, CeaseErrorSubcode, ErrorCode,
        HeaderErrorSubcode, MessageType, OpenErrorSubcode,
        OptionalParameterCode, PathAttributeTypeCode, PathOrigin, Safi,
        UpdateErrorSubcode,
    };

    pub use crate::v4::messages::Afi;
}
