// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, RequestContext, TypedBody,
};

use mg_api::{
    MribAddStaticRequest, MribDeleteStaticRequest,
    MribRpfRebuildIntervalRequest, MribRpfRebuildIntervalResponse,
    MribStatusQuery, RouteOriginFilter,
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

pub async fn mrib_status_imported(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<MribStatusQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let ctx = rqctx.context();
    let q = query.into_inner();
    let routes = ctx.db.mrib_list(
        q.address_family,
        origin_to_static_only(q.route_origin),
        false, // `mrib_in`
    );
    Ok(HttpResponseOk(routes))
}

pub async fn mrib_status_installed(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<MribStatusQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let ctx = rqctx.context();
    let q = query.into_inner();
    let routes = ctx.db.mrib_list(
        q.address_family,
        origin_to_static_only(q.route_origin),
        true, // `mrib_loc`
    );
    Ok(HttpResponseOk(routes))
}

pub async fn mrib_get_route(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<mg_api::MribRouteQuery>,
) -> Result<HttpResponseOk<MulticastRoute>, HttpError> {
    let ctx = rqctx.context();
    let q = query.into_inner();

    // Build the key from query params
    let group = match q.group {
        IpAddr::V4(v4) => MulticastAddr::try_from(v4).map_err(|e| {
            HttpError::for_bad_request(
                None,
                format!("invalid group address: {e}"),
            )
        })?,
        IpAddr::V6(v6) => MulticastAddr::try_from(v6).map_err(|e| {
            HttpError::for_bad_request(
                None,
                format!("invalid group address: {e}"),
            )
        })?,
    };

    let key = MulticastRouteKey {
        source: q.source,
        group,
        vni: q.vni,
    };

    // Look up in `mrib_in` (all imported routes)
    let route = ctx.db.get_mcast_route(&key).ok_or_else(|| {
        HttpError::for_not_found(None, format!("route {key} not found"))
    })?;

    Ok(HttpResponseOk(route))
}

pub async fn mrib_get_selected_route(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: dropshot::Query<mg_api::MribRouteQuery>,
) -> Result<HttpResponseOk<MulticastRoute>, HttpError> {
    let ctx = rqctx.context();
    let q = query.into_inner();

    // Build the key from query params
    let group = match q.group {
        IpAddr::V4(v4) => MulticastAddr::try_from(v4).map_err(|e| {
            HttpError::for_bad_request(
                None,
                format!("invalid group address: {e}"),
            )
        })?,
        IpAddr::V6(v6) => MulticastAddr::try_from(v6).map_err(|e| {
            HttpError::for_bad_request(
                None,
                format!("invalid group address: {e}"),
            )
        })?,
    };

    let key = MulticastRouteKey {
        source: q.source,
        group,
        vni: q.vni,
    };

    // Look up in `mrib_loc` (installed/selected routes)
    let route = ctx.db.get_selected_mcast_route(&key).ok_or_else(|| {
        HttpError::for_not_found(
            None,
            format!("route {key} not found in mrib_loc"),
        )
    })?;

    Ok(HttpResponseOk(route))
}

pub async fn mrib_static_add(
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

pub async fn mrib_static_delete(
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

pub async fn mrib_static_list(
    rqctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let ctx = rqctx.context();
    let routes = ctx.db.get_static_mcast_routes().map_err(Error::from)?;
    Ok(HttpResponseOk(routes))
}

pub async fn mrib_get_rpf_rebuild_interval(
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

pub async fn mrib_set_rpf_rebuild_interval(
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
