// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::v1::policy::ImportExportPolicy;
use crate::v1::prefix::Prefix;
use crate::v4::policy::{ImportExportPolicy4, ImportExportPolicy6};
use std::collections::BTreeSet;

impl ImportExportPolicy {
    /// Extract IPv4 prefixes from this policy as a typed IPv4 policy.
    ///
    /// If this policy is `NoFiltering`, returns `ImportExportPolicy4::NoFiltering`.
    /// If this policy is `Allow(prefixes)`, returns only the IPv4 prefixes.
    /// If the policy has prefixes but none are IPv4, returns `NoFiltering` for IPv4.
    pub fn as_ipv4_policy(&self) -> ImportExportPolicy4 {
        ImportExportPolicy4::from(self.clone())
    }

    /// Extract IPv6 prefixes from this policy as a typed IPv6 policy.
    ///
    /// If this policy is `NoFiltering`, returns `ImportExportPolicy6::NoFiltering`.
    /// If this policy is `Allow(prefixes)`, returns only the IPv6 prefixes.
    /// If the policy has prefixes but none are IPv6, returns `NoFiltering` for IPv6.
    pub fn as_ipv6_policy(&self) -> ImportExportPolicy6 {
        ImportExportPolicy6::from(self.clone())
    }

    /// Combine IPv4 and IPv6 policies into a legacy mixed-AF policy.
    ///
    /// - If both are `NoFiltering`, returns `NoFiltering`
    /// - Otherwise, combines the allowed prefixes from both into a single set
    pub fn from_per_af_policies(
        v4: &ImportExportPolicy4,
        v6: &ImportExportPolicy6,
    ) -> Self {
        match (v4, v6) {
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::NoFiltering,
            ) => ImportExportPolicy::NoFiltering,
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::NoFiltering,
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                ImportExportPolicy::Allow(prefixes)
            }
            (
                ImportExportPolicy4::NoFiltering,
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let prefixes: BTreeSet<Prefix> =
                    v6_prefixes.iter().map(|p| Prefix::V6(*p)).collect();
                ImportExportPolicy::Allow(prefixes)
            }
            (
                ImportExportPolicy4::Allow(v4_prefixes),
                ImportExportPolicy6::Allow(v6_prefixes),
            ) => {
                let mut prefixes: BTreeSet<Prefix> =
                    v4_prefixes.iter().map(|p| Prefix::V4(*p)).collect();
                prefixes.extend(v6_prefixes.iter().map(|p| Prefix::V6(*p)));
                ImportExportPolicy::Allow(prefixes)
            }
        }
    }
}
