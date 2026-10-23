// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Geneve Virtual Network Identifier (VNI).

// TODO: replace with a validated `Vni` newtype in oxnet, shared with
// `omicron_common::api::external::Vni` and `oxide_vpc::api::Vni`.

use std::fmt::{self, Formatter};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Error raised while validating a [`Vni`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VniError {
    /// The value exceeds the 24-bit Geneve maximum.
    #[error("VNI {value} exceeds the maximum 24-bit value {}", Vni::MAX_VNI)]
    OutOfRange { value: u32 },
}

/// A validated Geneve Virtual Network Identifier.
///
/// Wraps a 24-bit VNI, rejecting any value above [`Vni::MAX_VNI`] at
/// construction and deserialization.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "u32", into = "u32")]
pub struct Vni(#[schemars(range(max = 0xFF_FFFF))] u32);

impl Vni {
    /// Maximum Geneve VNI value.
    ///
    /// Virtual Network Identifiers are constrained to 24-bit values per the
    /// Geneve specification ([RFC 8926] §3.4).
    ///
    /// [RFC 8926]: https://www.rfc-editor.org/rfc/rfc8926.html
    pub const MAX_VNI: u32 = 0xFF_FFFF;

    /// Default VNI for rack-wide multicast groups (no VPC association).
    ///
    /// This is currently the only VNI used for multicast.
    ///
    /// All multicast traffic shares one rack-wide namespace, and there is no
    /// per-VPC isolation of multicast addresses. The value is low-numbered
    /// to prevent collision with user-chosen VNIs.
    pub const DEFAULT_MULTICAST: Self = Self(77);

    /// Create a validated VNI.
    ///
    /// # Errors
    ///
    /// Returns [`VniError::OutOfRange`] if `value` exceeds [`Vni::MAX_VNI`].
    ///
    /// # Examples
    ///
    /// ```
    /// use client_common::vni::Vni;
    ///
    /// assert!(Vni::new(77).is_ok());
    /// assert!(Vni::new(Vni::MAX_VNI + 1).is_err());
    /// ```
    pub const fn new(value: u32) -> Result<Self, VniError> {
        if value > Self::MAX_VNI {
            return Err(VniError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Return the inner 24-bit value.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Vni {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<u32> for Vni {
    type Error = VniError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Vni> for u32 {
    fn from(vni: Vni) -> Self {
        vni.0
    }
}

#[cfg(test)]
mod tests {
    use omicron_common::api::external::Vni as CanonicalVni;

    use super::*;

    /// Assert that the locally copied VNI literals are equivalent to their
    /// `omicron_common::api::external::Vni` originals in order to avoid drift.
    #[test]
    fn vni_constants_match_canonical_values() {
        assert_eq!(Vni::MAX_VNI, CanonicalVni::MAX_VNI);
        assert_eq!(
            Vni::DEFAULT_MULTICAST.as_u32(),
            CanonicalVni::DEFAULT_MULTICAST_VNI.as_u32()
        );
    }

    /// [`Vni::new`] accepts the bounds of the range and rejects values just
    /// above it and at `u32::MAX`.
    #[test]
    fn vni_accepts_bounds_rejects_out_of_range() {
        assert_eq!(Vni::new(0).unwrap().as_u32(), 0);
        assert_eq!(Vni::new(Vni::MAX_VNI).unwrap().as_u32(), Vni::MAX_VNI);
        assert!(Vni::new(Vni::MAX_VNI + 1).is_err());
        assert!(Vni::new(u32::MAX).is_err());
    }

    #[test]
    fn vni_schema_bounds_match_max_vni() {
        let schema = serde_json::to_value(schemars::schema_for!(Vni)).unwrap();
        assert_eq!(schema["type"], "integer");
        assert_eq!(schema["format"], "uint32");
        assert_eq!(schema["minimum"].as_f64(), Some(0.0));
        assert_eq!(schema["maximum"].as_f64(), Some(f64::from(Vni::MAX_VNI)));
    }
}
