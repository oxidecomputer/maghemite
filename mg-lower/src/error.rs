// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("dpd error {0}")]
    Dpd(#[from] dpd_client::Error<dpd_client::types::Error>),

    #[error("ddm error {0}")]
    Ddm(#[from] ddm_admin_client::Error<ddm_admin_client::types::Error>),

    #[error("tfport error {0}")]
    Tfport(String),

    #[error("no nexthop route {0}")]
    NoNexthopRoute(String),

    #[error("libnet error route {0}")]
    LibnetRoute(#[from] libnet::route::Error),

    #[error("oxnet ipnet prefix error {0}")]
    OxnetIpnetPrevix(#[from] oxnet::IpNetPrefixError),
}
