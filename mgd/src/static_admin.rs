// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::HandlerContext, register};
use dropshot::{
    endpoint, ApiDescription, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use rdb::{Path, Prefix4, StaticRouteKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::Arc,
};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddStaticRoute4Request {
    routes: StaticRoute4List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteStaticRoute4Request {
    routes: StaticRoute4List,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute4List {
    list: Vec<StaticRoute4>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StaticRoute4 {
    pub prefix: Prefix4,
    pub nexthop: Ipv4Addr,
    pub vlan_id: Option<u16>,
    pub rib_priority: u8,
}

impl From<StaticRoute4> for StaticRouteKey {
    fn from(val: StaticRoute4) -> Self {
        StaticRouteKey {
            prefix: val.prefix.into(),
            nexthop: val.nexthop.into(),
            vlan_id: val.vlan_id,
            rib_priority: val.rib_priority,
        }
    }
}

pub(crate) fn api_description(api: &mut ApiDescription<Arc<HandlerContext>>) {
    register!(api, static_add_v4_route);
    register!(api, static_remove_v4_route);
    register!(api, static_list_v4_routes);
}

#[endpoint { method = PUT, path = "/static/route4" }]
pub async fn static_add_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddStaticRoute4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();
    for r in routes {
        let path = Path::for_static(r.nexthop, r.vlan_id, r.rib_priority);
        ctx.context()
            .db
            .add_prefix_path(r.prefix, path, true)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    }
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/static/route4" }]
pub async fn static_remove_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute4Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();
    for r in routes {
        let path = Path::for_static(r.nexthop, r.vlan_id, r.rib_priority);
        ctx.context()
            .db
            .remove_prefix_path(r.prefix, path, true)
            .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    }
    Ok(HttpResponseDeleted())
}

pub type GetRibResult = BTreeMap<String, BTreeSet<Path>>;

#[endpoint { method = GET, path = "/static/route4" }]
pub async fn static_list_v4_routes(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<GetRibResult>, HttpError> {
    let static_rib = ctx
        .context()
        .db
        .static_rib()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();

    Ok(HttpResponseOk(static_rib))
}
