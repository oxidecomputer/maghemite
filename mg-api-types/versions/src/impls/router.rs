// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Display and helper impls for `crate::latest::router` types.

use crate::latest::bgp::peer::PeerId;
use crate::latest::router::{BgpSpec, RouterId};
use std::fmt::{self, Formatter};

impl RouterId {
    pub fn new_random() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for RouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BgpSpec {
    pub fn peer_ids(&self) -> impl Iterator<Item = PeerId> + '_ {
        let numbered = self
            .peers
            .values()
            .flatten()
            .map(|p| PeerId::Ip(p.host.ip()));
        let unnumbered = self
            .unnumbered_peers
            .values()
            .flatten()
            .map(|p| PeerId::Interface(p.interface.clone()));
        numbered.chain(unnumbered)
    }
}
