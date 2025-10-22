// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::HandlerContext, register};
use dropshot::{
    endpoint, ApiDescription, HttpError, HttpResponseOk, Query, RequestContext,
};
use rdb::{
    types::{AddressFamily, ProtocolFilter},
    Path, Prefix,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RibQuery {
    /// Filter by address family
    #[serde(default)]
    pub address_family: AddressFamily,
    /// Filter by protocol (optional)
    pub protocol: Option<ProtocolFilter>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
pub struct Rib(BTreeMap<String, BTreeSet<Path>>);

impl From<rdb::db::Rib> for Rib {
    fn from(value: rdb::db::Rib) -> Self {
        Rib(value.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

pub(crate) fn api_description(api: &mut ApiDescription<Arc<HandlerContext>>) {
    register!(api, get_imported);
    register!(api, get_selected);
}

#[endpoint { method = GET, path = "/rib/status/imported" }]
pub async fn get_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let imported = ctx.db.full_rib(query.address_family);
    let filtered = filter_rib_by_protocol(imported, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

#[endpoint { method = GET, path = "/rib/status/selected" }]
pub async fn get_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let selected = ctx.db.loc_rib(query.address_family);
    let filtered = filter_rib_by_protocol(selected, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

fn filter_rib_by_protocol(
    rib: BTreeMap<Prefix, BTreeSet<Path>>,
    protocol_filter: Option<ProtocolFilter>,
) -> BTreeMap<Prefix, BTreeSet<Path>> {
    match protocol_filter {
        None => rib,
        Some(filter) => {
            let mut filtered = BTreeMap::new();

            for (prefix, paths) in rib {
                let filtered_paths: BTreeSet<Path> = paths
                    .into_iter()
                    .filter(|path| match filter {
                        ProtocolFilter::Bgp => path.bgp.is_some(),
                        ProtocolFilter::Static => path.bgp.is_none(),
                    })
                    .collect();

                if !filtered_paths.is_empty() {
                    filtered.insert(prefix, filtered_paths);
                }
            }

            filtered
        }
    }
}
