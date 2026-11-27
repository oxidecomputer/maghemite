// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::latest::admin::PrefixKind;

impl std::fmt::Display for PrefixKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Underlay => write!(f, "underlay"),
            Self::Bootstrap => write!(f, "bootstrap"),
        }
    }
}

impl std::str::FromStr for PrefixKind {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "underlay" => Ok(Self::Underlay),
            "bootstrap" => Ok(Self::Bootstrap),
            _ => Err(r#"Prefix kind must be "underlay" or "bootstrap""#),
        }
    }
}
