// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use dropshot::{
    endpoint, HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use rdb::{Prefix4, Route4ImportKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, sync::Arc};

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
}

impl From<StaticRoute4> for Route4ImportKey {
    fn from(val: StaticRoute4) -> Self {
        Route4ImportKey {
            prefix: val.prefix,
            nexthop: val.nexthop,
            id: 0,
            priority: 0,
        }
    }
}

impl From<Route4ImportKey> for StaticRoute4 {
    fn from(value: Route4ImportKey) -> Self {
        Self {
            prefix: value.prefix,
            nexthop: value.nexthop,
        }
    }
}

#[endpoint { method = PUT, path = "/static/route4" }]
pub async fn static_add_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddStaticRoute4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<Route4ImportKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();
    for r in routes {
        ctx.context().db.set_nexthop4(r);
    }
    Ok(HttpResponseUpdatedNoContent())
}

#[endpoint { method = DELETE, path = "/static/route4" }]
pub async fn static_remove_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute4Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<Route4ImportKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();
    for r in routes {
        ctx.context().db.remove_nexthop4(r);
    }
    Ok(HttpResponseDeleted())
}

#[endpoint { method = GET, path = "/static/route4" }]
pub async fn static_list_v4_routes(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<StaticRoute4List>, HttpError> {
    let list = ctx
        .context()
        .db
        .get_imported4()
        .into_iter()
        .filter(|x| x.id == 0) // indicates not from bgp
        .map(Into::into)
        .collect();
    Ok(HttpResponseOk(StaticRoute4List { list }))
}
