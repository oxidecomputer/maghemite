// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use dropshot::{
    HttpError, HttpResponseOk, HttpResponseUpdatedNoContent, Query,
    RequestContext, TypedBody,
};
use mg_api_types::rib::{
    BestpathFanoutRequest, BestpathFanoutResponse, Rib, RibQuery,
};
use mg_api_types_versions::{v1, v2};
use rdb::RibExt;
use std::sync::Arc;

// Prior version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED):
// BgpPathProperties.peer is IpAddr.
pub async fn get_rib_imported_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<v2::rib::RibQuery>,
) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let imported = ctx.db.full_rib(query.address_family);
    let filtered = imported.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(v1::rib::Rib::from(
        filtered.into_latest_api_rib(),
    )))
}

pub async fn get_rib_selected_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<v2::rib::RibQuery>,
) -> Result<HttpResponseOk<v1::rib::Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let selected = ctx.db.loc_rib(query.address_family);
    let filtered = selected.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(v1::rib::Rib::from(
        filtered.into_latest_api_rib(),
    )))
}

// Latest version (VERSION_UNNUMBERED+): BgpPathProperties.peer is PeerId enum.
pub async fn get_rib_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let imported = ctx.db.full_rib(query.address_family);
    let filtered = imported.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(filtered.into_latest_api_rib()))
}

pub async fn get_rib_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let selected = ctx.db.loc_rib(query.address_family);
    let filtered = selected.filter_by_protocol(query.protocol);
    Ok(HttpResponseOk(filtered.into_latest_api_rib()))
}

pub async fn read_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
    let ctx = ctx.context();
    let fanout = ctx
        .db
        .get_bestpath_fanout()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseOk(BestpathFanoutResponse { fanout }))
}

pub async fn update_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<BestpathFanoutRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = ctx.context();
    let rq = request.into_inner();

    ctx.db
        .set_bestpath_fanout(rq.fanout)
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseUpdatedNoContent())
}
