// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Error type for UnnumberedManager operations.
#[derive(Debug, Clone)]
pub enum UnnumberedError {
    /// Interface not found on the system
    InterfaceNotFound(String),
    /// Interface exists but is not IPv6
    NotIpv6(String),
    /// Other interface resolution error
    ResolutionFailed { interface: String, reason: String },
}

impl std::fmt::Display for UnnumberedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceNotFound(iface) => {
                write!(f, "interface '{}' not found", iface)
            }
            Self::NotIpv6(iface) => {
                write!(f, "interface '{}' is not IPv6", iface)
            }
            Self::ResolutionFailed { interface, reason } => {
                write!(
                    f,
                    "failed to resolve interface '{}': {}",
                    interface, reason
                )
            }
        }
    }
}

impl std::error::Error for UnnumberedError {}
