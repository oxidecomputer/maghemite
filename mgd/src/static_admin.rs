// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::validation::validate_static_routes;
use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use mg_api_types::rdb::rib::AddressFamily;
use mg_api_types::rib::GetRibResult;
use mg_api_types::static_routes::{
    AddStaticRoute4Request, AddStaticRoute6Request, DeleteStaticRoute4Request,
    DeleteStaticRoute6Request, StaticRoute4, StaticRoute6,
};
use mg_api_types::switch::SwitchIdentifiers;
use rdb::StaticRouteKey;
use std::{collections::BTreeMap, sync::Arc};

// `From<StaticRouteN>` impls cannot live in `mg-api-types-versions` (would
// force a `rdb` dep) nor in `rdb` (would force an `mg-api-types-versions` dep).
// Both source and target types are foreign to `mgd`, so we expose the
// conversion as free fns here at the call site.
fn static_route_key_from_v4(v: StaticRoute4) -> StaticRouteKey {
    // Compile barrier: a new StaticRoute4 field will fail to bind here,
    // forcing a deliberate decision about how (or whether) it should
    // appear in the rdb runtime key.
    let StaticRoute4 {
        prefix,
        nexthop,
        vlan_id,
        rib_priority,
    } = v;
    StaticRouteKey {
        prefix: prefix.into(),
        nexthop,
        vlan_id,
        rib_priority,
    }
}

fn static_route_key_from_v6(v: StaticRoute6) -> StaticRouteKey {
    // Compile barrier: a new StaticRoute6 field will fail to bind here,
    // forcing a deliberate decision about how (or whether) it should
    // appear in the rdb runtime key.
    let StaticRoute6 {
        prefix,
        nexthop,
        vlan_id,
        rib_priority,
    } = v;
    StaticRouteKey {
        prefix: prefix.into(),
        nexthop: nexthop.into(),
        vlan_id,
        rib_priority,
    }
}

pub async fn static_add_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddStaticRoute4Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(static_route_key_from_v4)
        .collect();

    validate_static_routes(&routes)?;

    ctx.context()
        .db
        .add_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute4Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(static_route_key_from_v4)
        .collect();
    ctx.context()
        .db
        .remove_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseDeleted())
}

pub async fn static_list_v4_routes(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<GetRibResult>, HttpError> {
    let static_db = ctx
        .context()
        .db
        .get_static(Some(AddressFamily::Ipv4))
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let mut static_rib: GetRibResult = BTreeMap::new();
    for srk in static_db {
        let key = srk.prefix.to_string();
        let paths = static_rib.entry(key).or_default();
        paths.insert(srk.into());
    }

    Ok(HttpResponseOk(static_rib))
}

pub async fn static_add_v6_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddStaticRoute6Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(static_route_key_from_v6)
        .collect();

    validate_static_routes(&routes)?;

    ctx.context()
        .db
        .add_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_v6_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute6Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(static_route_key_from_v6)
        .collect();
    ctx.context()
        .db
        .remove_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseDeleted())
}

pub async fn static_list_v6_routes(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<GetRibResult>, HttpError> {
    let static_db = ctx
        .context()
        .db
        .get_static(Some(AddressFamily::Ipv6))
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;

    let mut static_rib: GetRibResult = BTreeMap::new();
    for srk in static_db {
        let key = srk.prefix.to_string();
        let paths = static_rib.entry(key).or_default();
        paths.insert(srk.into());
    }

    Ok(HttpResponseOk(static_rib))
}

pub(crate) async fn switch_identifiers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError> {
    let slot = ctx.context().db.slot();
    Ok(HttpResponseOk(SwitchIdentifiers { slot }))
}
