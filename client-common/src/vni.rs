// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Geneve Virtual Network Identifier (VNI).
//!
//! Lives in the cycle-free leaf crate so the API-types crates consumed by
//! Omicron can share a single definition without depending on
//! `omicron_common`, which would form a dependency cycle.

// TODO: `omicron_common::api::external::Vni` and `oxide_vpc::api::Vni` carry
// independent copies, forcing consumers to assert their constants stay equal.
// Consolidate into `oxnet`, the cycle-free leaf crate that maghemite,
// dendrite, and omicron already share, so the duplication can be removed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Formatter};

/// Error raised while validating a [`Vni`].
#[derive(thiserror::Error, Debug)]
pub enum VniError {
    /// The value exceeds the 24-bit Geneve maximum.
    #[error("VNI {value} exceeds the maximum 24-bit value {}", Vni::MAX_VNI)]
    OutOfRange { value: u32 },
}

/// A validated Geneve Virtual Network Identifier.
///
/// Wraps a 24-bit VNI, rejecting any value above [`Vni::MAX_VNI`] at
/// construction and deserialization so an out-of-range identifier is
/// unrepresentable.
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
#[schemars(transparent)]
pub struct Vni(u32);

impl Vni {
    /// Maximum Geneve VNI value.
    ///
    /// Virtual Network Identifiers are constrained to 24-bit values per the
    /// Geneve specification (RFC 8926 Section 3.3).
    pub const MAX_VNI: u32 = 0xFF_FFFF;

    /// Default VNI for fleet-wide multicast routing.
    ///
    /// A low-numbered VNI chosen to avoid colliding with user VNIs, though
    /// it is not yet within the Oxide-reserved range.
    pub const DEFAULT_MULTICAST: Self = Self(77);

    /// Create a validated VNI.
    ///
    /// # Errors
    ///
    /// Returns [`VniError::OutOfRange`] if `value` exceeds [`Vni::MAX_VNI`],
    /// the largest 24-bit Geneve VNI.
    ///
    /// # Examples
    ///
    /// ```
    /// use client_common::vni::Vni;
    ///
    /// assert!(Vni::new(77).is_ok());
    /// assert!(Vni::new(Vni::MAX_VNI + 1).is_err());
    /// ```
    pub fn new(value: u32) -> Result<Self, VniError> {
        if value > Self::MAX_VNI {
            return Err(VniError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Return the underlying 24-bit value.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Vni {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

    /// Assert the locally copied VNI literals equal their
    /// `omicron_common::api::external::Vni` originals so they cannot drift.
    ///
    /// `omicron_common` is a dev-dependency only, so it does not appear in the
    /// normal dependency tree the no-omicron CI check inspects.
    #[test]
    fn vni_constants_match_canonical_values() {
        assert_eq!(Vni::MAX_VNI, CanonicalVni::MAX_VNI);
        assert_eq!(
            Vni::DEFAULT_MULTICAST.as_u32(),
            CanonicalVni::DEFAULT_MULTICAST_VNI.as_u32()
        );
    }

    /// The [`Vni`] newtype accepts in-range values and rejects values above
    /// [`Vni::MAX_VNI`], enforcing the 24-bit invariant at construction.
    #[test]
    fn vni_rejects_out_of_range() {
        assert_eq!(Vni::new(0).unwrap().as_u32(), 0);
        assert_eq!(Vni::new(Vni::MAX_VNI).unwrap().as_u32(), Vni::MAX_VNI);
        assert!(Vni::new(Vni::MAX_VNI + 1).is_err());
        assert!(Vni::new(u32::MAX).is_err());
    }
}
