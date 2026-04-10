// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::validation::validate_prefixes;
use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};
use mg_types::rib::GetRibResult;
use mg_types::static_routes::{
    AddStaticRoute4Request, AddStaticRoute6Request, DeleteStaticRoute4Request,
    DeleteStaticRoute6Request,
};
use mg_types::switch::SwitchIdentifiers;
use mg_types_versions::v1::static_routes::{
    AddStaticRoute4Request as AddStaticRoute4V1Request,
    DeleteStaticRoute4Request as DeleteStaticRoute4V1Request,
};
use mg_types_versions::v2::static_routes::{
    AddStaticRoute6Request as AddStaticRoute6V1Request,
    DeleteStaticRoute6Request as DeleteStaticRoute6V1Request,
};
use rdb::{AddressFamily, Prefix, StaticRouteKey};
use std::{collections::BTreeMap, sync::Arc};

// V1 handlers (pre-SPRING_CLEANING): typed nexthop per AF

pub async fn static_add_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddStaticRoute4V1Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();

    // Validate that all prefixes have host bits unset
    let prefixes: Vec<Prefix> = routes.iter().map(|r| r.prefix).collect();
    validate_prefixes(&prefixes)?;

    ctx.context()
        .db
        .add_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_v4_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute4V1Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
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
    request: TypedBody<AddStaticRoute6V1Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();

    // Validate that all prefixes have host bits unset
    let prefixes: Vec<Prefix> = routes.iter().map(|r| r.prefix).collect();
    validate_prefixes(&prefixes)?;

    ctx.context()
        .db
        .add_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_v6_route(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute6V1Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
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

// V2 handlers (VERSION_SPRING_CLEANING+): IpAddr nexthop

pub async fn static_add_v4_route_v2(
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

    let prefixes: Vec<Prefix> = routes.iter().map(|r| r.prefix).collect();
    validate_prefixes(&prefixes)?;

    ctx.context()
        .db
        .add_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_v4_route_v2(
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
    ctx.context()
        .db
        .remove_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseDeleted())
}

pub async fn static_add_v6_route_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<AddStaticRoute6Request>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();

    let prefixes: Vec<Prefix> = routes.iter().map(|r| r.prefix).collect();
    validate_prefixes(&prefixes)?;

    ctx.context()
        .db
        .add_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_v6_route_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<DeleteStaticRoute6Request>,
) -> Result<HttpResponseDeleted, HttpError> {
    let routes: Vec<StaticRouteKey> = request
        .into_inner()
        .routes
        .list
        .into_iter()
        .map(Into::into)
        .collect();
    ctx.context()
        .db
        .remove_static_routes(&routes)
        .map_err(|e| HttpError::for_internal_error(e.to_string()))?;
    Ok(HttpResponseDeleted())
}

pub(crate) async fn switch_identifiers(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError> {
    let slot = ctx.context().db.slot();
    Ok(HttpResponseOk(SwitchIdentifiers { slot }))
}
