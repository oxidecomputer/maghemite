// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::Arc;
use std::time::Duration;

use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};

use mg_api::{
    MribAddStaticRequest, MribDeleteStaticRequest, MribQuery,
    MribRpfRebuildIntervalRequest, MribRpfRebuildIntervalResponse,
    RouteOriginFilter,
};
use rdb::types::{
    MulticastAddr, MulticastRoute, MulticastRouteKey, MulticastRouteSource,
};

use crate::admin::HandlerContext;
use crate::error::Error;

/// Convert [`RouteOriginFilter`] to the `static_only` parameter
/// used by [`rdb::Db::mrib_list`].
fn origin_to_static_only(origin: Option<RouteOriginFilter>) -> Option<bool> {
    match origin {
        None => None,
        Some(RouteOriginFilter::Static) => Some(true),
        Some(RouteOriginFilter::Dynamic) => Some(false),
    }
}

pub async fn get_mrib_imported(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<MribQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let ctx = rqctx.context();
    let q = query.into_inner();

    // If group is provided, look up a specific route
    if let Some(group_addr) = q.group {
        let group = MulticastAddr::try_from(group_addr).map_err(|e| {
            HttpError::for_bad_request(
                None,
                format!("invalid group address: {e}"),
            )
        })?;
        let key = MulticastRouteKey::new(q.source, group, q.vni)
            .map_err(|e| HttpError::for_bad_request(None, format!("{e}")))?;
        let route = ctx.db.get_mcast_route(&key).ok_or_else(|| {
            HttpError::for_not_found(None, format!("route {key} not found"))
        })?;
        return Ok(HttpResponseOk(vec![route]));
    }

    // Otherwise, list all routes with filters
    let routes = ctx.db.mrib_list(
        q.address_family,
        origin_to_static_only(q.route_origin),
        false, // `mrib_in`
    );
    Ok(HttpResponseOk(routes))
}

pub async fn get_mrib_selected(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<MribQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let ctx = rqctx.context();
    let q = query.into_inner();

    // If group is provided, look up a specific route
    if let Some(group_addr) = q.group {
        let group = MulticastAddr::try_from(group_addr).map_err(|e| {
            HttpError::for_bad_request(
                None,
                format!("invalid group address: {e}"),
            )
        })?;
        let key = MulticastRouteKey::new(q.source, group, q.vni)
            .map_err(|e| HttpError::for_bad_request(None, format!("{e}")))?;
        let route = ctx.db.get_selected_mcast_route(&key).ok_or_else(|| {
            HttpError::for_not_found(
                None,
                format!("route {key} not found in mrib_loc"),
            )
        })?;
        return Ok(HttpResponseOk(vec![route]));
    }

    // Otherwise, list all routes with filters
    let routes = ctx.db.mrib_list(
        q.address_family,
        origin_to_static_only(q.route_origin),
        true, // `mrib_loc`
    );
    Ok(HttpResponseOk(routes))
}

pub async fn static_add_mcast_route(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MribAddStaticRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = rqctx.context();
    let body = request.into_inner();

    // Convert input to full `MulticastRoute` with timestamps
    let routes: Vec<MulticastRoute> = body
        .routes
        .into_iter()
        .map(|input| {
            let mut route = MulticastRoute::new(
                input.key,
                input.underlay_group,
                MulticastRouteSource::Static,
            );
            route.underlay_nexthops =
                input.underlay_nexthops.into_iter().collect();
            route
        })
        .collect();

    // Validate routes before adding
    for route in &routes {
        route.validate().map_err(|e| {
            HttpError::for_bad_request(None, format!("validation error: {e}"))
        })?;
    }

    ctx.db
        .add_static_mcast_routes(&routes)
        .map_err(Error::from)?;
    Ok(HttpResponseUpdatedNoContent())
}

pub async fn static_remove_mcast_route(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MribDeleteStaticRequest>,
) -> Result<HttpResponseDeleted, HttpError> {
    let ctx = rqctx.context();
    let body = request.into_inner();
    ctx.db
        .remove_static_mcast_routes(&body.keys)
        .map_err(Error::from)?;
    Ok(HttpResponseDeleted())
}

pub async fn static_list_mcast_routes(
    rqctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let ctx = rqctx.context();
    let routes = ctx.db.get_static_mcast_routes().map_err(Error::from)?;
    Ok(HttpResponseOk(routes))
}

pub async fn read_mrib_rpf_rebuild_interval(
    rqctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<MribRpfRebuildIntervalResponse>, HttpError> {
    let ctx = rqctx.context();
    let interval = ctx
        .db
        .get_mrib_rpf_rebuild_interval()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;
    Ok(HttpResponseOk(MribRpfRebuildIntervalResponse {
        interval_ms: interval.as_millis() as u64,
    }))
}

pub async fn update_mrib_rpf_rebuild_interval(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MribRpfRebuildIntervalRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = rqctx.context();
    let body = request.into_inner();
    let interval = Duration::from_millis(body.interval_ms);
    ctx.db
        .set_mrib_rpf_rebuild_interval(interval)
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;
    Ok(HttpResponseUpdatedNoContent())
}
