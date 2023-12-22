// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("dpd error {0}")]
    Dpd(#[from] dpd_client::Error<dpd_client::types::Error>),
}
