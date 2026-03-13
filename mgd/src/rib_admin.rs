// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use dropshot::{
    HttpError, HttpResponseOk, HttpResponseUpdatedNoContent, Query,
    RequestContext, TypedBody,
};
use mg_api::{
    BestpathFanoutRequest, BestpathFanoutResponse, Rib, RibQuery, RibQueryV1,
    RibV1, RibV2, filter_rib_by_protocol,
};
use rdb::Prefix;
use std::collections::BTreeMap;
use std::sync::Arc;

// Original version (VERSION_IPV6_BASIC..VERSION_UNNUMBERED): BgpPathProperties.peer is IpAddr
pub async fn get_rib_imported(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQueryV1>,
) -> Result<HttpResponseOk<RibV1>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let imported = ctx.db.full_rib(query.address_family);
    let filtered = filter_rib_by_protocol(imported, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

pub async fn get_rib_selected(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQueryV1>,
) -> Result<HttpResponseOk<RibV1>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let selected = ctx.db.loc_rib(query.address_family);
    let filtered = filter_rib_by_protocol(selected, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

// VERSION_UNNUMBERED..VERSION_EXTENDED_NH_STATIC (PeerId, no origin/internal)
pub async fn get_rib_imported_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQueryV1>,
) -> Result<HttpResponseOk<RibV2>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let imported = ctx.db.full_rib(query.address_family);
    let filtered = filter_rib_by_protocol(imported, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

pub async fn get_rib_selected_v2(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQueryV1>,
) -> Result<HttpResponseOk<RibV2>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let selected = ctx.db.loc_rib(query.address_family);
    let filtered = filter_rib_by_protocol(selected, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

// VERSION_EXTENDED_NH_STATIC+ (BgpPathProperties with origin/internal)
pub async fn get_rib_imported_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let rib = if let Some(ref prefix_str) = query.prefix {
        let prefix: Prefix = prefix_str
            .parse()
            .map_err(|e: String| HttpError::for_bad_request(None, e))?;
        match ctx.db.get_imported_prefix(&prefix) {
            Some(paths) => BTreeMap::from([(prefix, paths)]),
            None => BTreeMap::new(),
        }
    } else {
        ctx.db.full_rib(query.address_family)
    };
    let filtered = filter_rib_by_protocol(rib, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

pub async fn get_rib_selected_v3(
    ctx: RequestContext<Arc<HandlerContext>>,
    query: Query<RibQuery>,
) -> Result<HttpResponseOk<Rib>, HttpError> {
    let ctx = ctx.context();
    let query = query.into_inner();
    let rib = if let Some(ref prefix_str) = query.prefix {
        let prefix: Prefix = prefix_str
            .parse()
            .map_err(|e: String| HttpError::for_bad_request(None, e))?;
        match ctx.db.get_selected_prefix(&prefix) {
            Some(paths) => BTreeMap::from([(prefix, paths)]),
            None => BTreeMap::new(),
        }
    } else {
        ctx.db.loc_rib(query.address_family)
    };
    let filtered = filter_rib_by_protocol(rib, query.protocol);
    Ok(HttpResponseOk(filtered.into()))
}

pub async fn read_rib_bestpath_fanout(
    ctx: RequestContext<Arc<HandlerContext>>,
) -> Result<HttpResponseOk<BestpathFanoutResponse>, HttpError> {
    let ctx = ctx.context();
    let fanout = ctx
        .db
        .get_bestpath_fanout()
        .map_err(|e| HttpError::for_internal_error(format!("{e}")))?;

    Ok(HttpResponseOk(BestpathFanoutResponse { fanout }))
}

pub async fn update_rib_bestpath_fanout(
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
