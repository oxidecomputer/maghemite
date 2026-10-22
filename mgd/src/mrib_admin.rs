// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use dropshot::{
    HttpError, HttpResponseDeleted, HttpResponseOk,
    HttpResponseUpdatedNoContent, Query, RequestContext, TypedBody,
};
use mg_api_types::mrib::{
    MribAddStaticRequest, MribDeleteStaticRequest, MribQuery, MulticastRoute,
    MulticastRouteKey, MulticastSourceProtocol,
};
use rdb::{Db, MribTableExt};

use crate::admin::HandlerContext;
use crate::error::Error;

/// Which MRIB table a query targets: imported routes (`mrib_in`) or
/// selected routes (`mrib_loc`).
#[derive(Clone, Copy)]
enum MribTable {
    Imported,
    Selected,
}

fn get_mrib(
    db: &Db,
    query: MribQuery,
    table: MribTable,
) -> Result<Vec<MulticastRoute>, HttpError> {
    if let Some(group) = query.group {
        let key = MulticastRouteKey::new(query.source, group, query.vni)
            .map_err(Error::from)?;
        let route = match table {
            MribTable::Imported => db.get_mcast_route(&key),
            MribTable::Selected => db.get_selected_mcast_route(&key),
        };
        return route.map(|r| vec![r]).ok_or_else(|| {
            Error::NotFound(format!("multicast route {key}")).into()
        });
    }

    let routes = match table {
        MribTable::Imported => db.full_mrib(query.address_family),
        MribTable::Selected => db.loc_mrib(query.address_family),
    };
    Ok(routes
        .filter_by_origin(query.route_origin)
        .into_values()
        .collect())
}

pub async fn get_mrib_imported(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: Query<MribQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let routes =
        get_mrib(&rqctx.context().db, query.into_inner(), MribTable::Imported)?;
    Ok(HttpResponseOk(routes))
}

pub async fn get_mrib_selected(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: Query<MribQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let routes =
        get_mrib(&rqctx.context().db, query.into_inner(), MribTable::Selected)?;
    Ok(HttpResponseOk(routes))
}

pub async fn static_add_mcast_route(
    rqctx: RequestContext<Arc<HandlerContext>>,
    request: TypedBody<MribAddStaticRequest>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let ctx = rqctx.context();
    let routes: Vec<MulticastRoute> = request
        .into_inner()
        .routes
        .into_iter()
        .map(|input| {
            MulticastRoute::new(
                input.key,
                input.underlay_group,
                MulticastSourceProtocol::Static,
            )
        })
        .collect();
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
    ctx.db
        .remove_static_mcast_routes(&request.into_inner().keys)
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use mg_api_types::mrib::{
        MulticastAddr, RouteOriginFilter, StaticMulticastRoute,
        UnderlayMulticastIpv6, Vni,
    };
    use mg_api_types::rdb::rib::AddressFamily;

    use super::*;
    use crate::test::{TestServer, raw_status, status, test_db};

    fn underlay_group() -> UnderlayMulticastIpv6 {
        UnderlayMulticastIpv6::new(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1))
            .expect("valid test underlay address")
    }

    fn query(
        group: Option<MulticastAddr>,
        source: Option<IpAddr>,
    ) -> MribQuery {
        MribQuery {
            group,
            source,
            vni: Vni::DEFAULT_MULTICAST,
            address_family: None,
            route_origin: None,
        }
    }

    fn add_any_source(db: &Db, group: MulticastAddr) -> MulticastRouteKey {
        let key = MulticastRouteKey::any_source(group).expect("valid key");
        db.add_static_mcast_routes(&[MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        )])
        .expect("add route");
        key
    }

    #[test]
    fn group_lookup_miss_is_not_found() {
        let (db, _log) = test_db("mrib_admin_miss");
        let group = MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");

        for table in [MribTable::Imported, MribTable::Selected] {
            let err = get_mrib(&db, query(Some(group), None), table)
                .expect_err("empty MRIB should miss");
            assert_eq!(err.status_code, 404);
        }
    }

    #[test]
    fn invalid_key_is_bad_request() {
        let (db, _log) = test_db("mrib_admin_bad_key");
        let asm = MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let ssm = MulticastAddr::new_v4(232, 1, 1, 1).expect("valid mcast");
        let v6_source =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        for q in [query(Some(asm), Some(v6_source)), query(Some(ssm), None)] {
            let err = get_mrib(&db, q, MribTable::Imported)
                .expect_err("invalid (S,G) should be rejected");
            assert_eq!(err.status_code, 400);
        }
    }

    #[test]
    fn group_lookup_reads_requested_table() {
        let (db, _log) = test_db("mrib_admin_tables");
        let any_group =
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let any_key = add_any_source(&db, any_group);

        let sg_group =
            MulticastAddr::new_v4(239, 2, 2, 2).expect("valid mcast");
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let sg_key = MulticastRouteKey::new(
            Some(source),
            sg_group,
            Vni::DEFAULT_MULTICAST,
        )
        .expect("valid key");
        db.add_static_mcast_routes(&[MulticastRoute::new(
            sg_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        )])
        .expect("add route");

        for table in [MribTable::Imported, MribTable::Selected] {
            let got = get_mrib(&db, query(Some(any_group), None), table)
                .expect("route present");
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].key, any_key);
        }

        let sg_query = || query(Some(sg_group), Some(source));
        let got = get_mrib(&db, sg_query(), MribTable::Imported)
            .expect("imported route present");
        assert_eq!(got[0].key, sg_key);
        let err = get_mrib(&db, sg_query(), MribTable::Selected)
            .expect_err("unreachable source should not be selected");
        assert_eq!(err.status_code, 404);

        let list = |table| {
            get_mrib(&db, query(None, None), table).expect("list").len()
        };
        assert_eq!(list(MribTable::Imported), 2);
        assert_eq!(list(MribTable::Selected), 1);
    }

    #[test]
    fn list_applies_origin_and_ip_family_filters() {
        let (db, _log) = test_db("mrib_admin_filters");
        add_any_source(
            &db,
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast"),
        );

        let list = |route_origin, address_family| {
            let q = MribQuery {
                route_origin,
                address_family,
                ..query(None, None)
            };
            get_mrib(&db, q, MribTable::Imported).expect("list").len()
        };
        assert_eq!(list(None, None), 1);
        assert_eq!(list(Some(RouteOriginFilter::Static), None), 1);
        assert_eq!(list(Some(RouteOriginFilter::Dynamic), None), 0);
        assert_eq!(list(None, Some(AddressFamily::Ipv4)), 1);
        assert_eq!(list(None, Some(AddressFamily::Ipv6)), 0);
    }

    #[tokio::test]
    async fn http_static_route_lifecycle() {
        let server = TestServer::start("mrib_admin_http_lifecycle");
        let client = &server.client;
        let any_group =
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let any_key = MulticastRouteKey::any_source(any_group).expect("key");
        let sg_group = MulticastAddr::new_v6([0xff0e, 0, 0, 0, 0, 0, 0, 1])
            .expect("mcast");
        let source = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let sg_key = MulticastRouteKey::new(
            Some(source),
            sg_group,
            Vni::DEFAULT_MULTICAST,
        )
        .expect("key");

        client
            .static_add_mcast_route(&MribAddStaticRequest {
                routes: [any_key, sg_key]
                    .into_iter()
                    .map(|key| StaticMulticastRoute {
                        key,
                        underlay_group: underlay_group(),
                    })
                    .collect(),
            })
            .await
            .expect("add routes");

        let listed = client
            .static_list_mcast_routes()
            .await
            .expect("list static routes")
            .into_inner();
        let mut keys: Vec<_> = listed.iter().map(|r| r.key).collect();
        keys.sort();
        let mut want = vec![any_key, sg_key];
        want.sort();
        assert_eq!(keys, want);

        let got = client
            .get_mrib_imported(None, Some(&sg_group), None, Some(&source), None)
            .await
            .expect("look up (S,G) with omitted vni")
            .into_inner();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, sg_key);

        let err = client
            .get_mrib_selected(None, Some(&sg_group), None, Some(&source), None)
            .await
            .expect_err("unreachable source should not be selected");
        assert_eq!(status(&err), Some(404));

        let selected = client
            .get_mrib_selected(None, None, None, None, None)
            .await
            .expect("list selected")
            .into_inner();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].key, any_key);

        client
            .static_remove_mcast_route(&MribDeleteStaticRequest {
                keys: vec![any_key, sg_key],
            })
            .await
            .expect("remove routes");
        let imported = client
            .get_mrib_imported(None, None, None, None, None)
            .await
            .expect("list imported")
            .into_inner();
        assert!(imported.is_empty());
        let err = client
            .get_mrib_imported(None, Some(&any_group), None, None, None)
            .await
            .expect_err("removed route should miss");
        assert_eq!(status(&err), Some(404));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn http_rejects_invalid_requests() {
        let server = TestServer::start("mrib_admin_http_invalid");
        let client = &server.client;
        let get = http::Method::GET;

        for query in [
            "group=10.0.0.1",
            "group=ff04::1",
            "group=232.1.1.1",
            "group=239.1.1.1&source=2001:db8::1",
            "group=239.1.1.1&vni=16777216",
        ] {
            let path = format!("/mrib/status/imported?{query}");
            assert_eq!(
                raw_status(client, get.clone(), &path, None).await,
                400,
                "{query}"
            );
        }

        let ssm_without_source = concat!(
            r#"{"routes":[{"key":{"V4":{"group":"232.1.1.1","source":null}},"#,
            r#""underlay_group":"ff04::1"}]}"#,
        );
        let bad_underlay = concat!(
            r#"{"routes":[{"key":{"V4":{"group":"239.1.1.1","source":null}},"#,
            r#""underlay_group":"ff05::1"}]}"#,
        );
        for body in [ssm_without_source, bad_underlay] {
            assert_eq!(
                raw_status(
                    client,
                    http::Method::PUT,
                    "/static/mroute",
                    Some(body)
                )
                .await,
                400,
                "{body}"
            );
        }

        let listed = client
            .static_list_mcast_routes()
            .await
            .expect("list static routes")
            .into_inner();
        assert!(listed.is_empty());

        server.shutdown().await;
    }
}
