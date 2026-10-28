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
    MulticastSourceProtocol,
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
) -> Vec<MulticastRoute> {
    let routes = match table {
        MribTable::Imported => db.full_mrib(query.address_family()),
        MribTable::Selected => db.loc_mrib(query.address_family()),
    };
    routes
        .filter_by_origin(query.route_origin())
        .into_values()
        .filter(|route| query.matches(&route.key))
        .collect()
}

pub async fn get_mrib_imported(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: Query<MribQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let routes =
        get_mrib(&rqctx.context().db, query.into_inner(), MribTable::Imported);
    Ok(HttpResponseOk(routes))
}

pub async fn get_mrib_selected(
    rqctx: RequestContext<Arc<HandlerContext>>,
    query: Query<MribQuery>,
) -> Result<HttpResponseOk<Vec<MulticastRoute>>, HttpError> {
    let routes =
        get_mrib(&rqctx.context().db, query.into_inner(), MribTable::Selected);
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
        MulticastAddr, MulticastRouteKey, RouteOriginFilter,
        StaticMulticastRoute, UnderlayMulticastIpv6, Vni,
    };
    use mg_api_types::rdb::rib::AddressFamily;

    use super::*;
    use crate::test::{TestServer, raw_status, test_db};

    fn underlay_group() -> UnderlayMulticastIpv6 {
        UnderlayMulticastIpv6::new(Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1))
            .expect("valid test underlay address")
    }

    fn vni() -> Vni {
        Vni::new(77).expect("valid multicast test VNI")
    }

    fn query(
        group: Option<MulticastAddr>,
        source: Option<IpAddr>,
        vni: Option<Vni>,
    ) -> MribQuery {
        MribQuery::new(group, source, vni, None, None).expect("valid query")
    }

    fn add_route(db: &Db, key: MulticastRouteKey) -> MulticastRouteKey {
        db.add_static_mcast_routes(&[MulticastRoute::new(
            key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        )])
        .expect("add route");
        key
    }

    fn keys(db: &Db, q: MribQuery, table: MribTable) -> Vec<MulticastRouteKey> {
        let mut keys: Vec<_> =
            get_mrib(db, q, table).into_iter().map(|r| r.key).collect();
        keys.sort();
        keys
    }

    fn add_any_source(db: &Db, group: MulticastAddr) -> MulticastRouteKey {
        add_route(
            db,
            MulticastRouteKey::any_source(group, vni()).expect("valid key"),
        )
    }

    #[test]
    fn group_filter_miss_is_empty() {
        let (db, _log) = test_db("mrib_admin_miss");
        add_any_source(
            &db,
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast"),
        );
        let other = MulticastAddr::new_v4(239, 9, 9, 9).expect("valid mcast");

        for table in [MribTable::Imported, MribTable::Selected] {
            assert!(
                keys(&db, query(Some(other), None, None), table).is_empty()
            );
        }
    }

    #[test]
    fn filters_match_independently() {
        let (db, _log) = test_db("mrib_admin_filters_independent");
        let group = MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let other_group =
            MulticastAddr::new_v4(239, 2, 2, 2).expect("valid mcast");
        let other_vni = Vni::new(100).expect("valid VNI");
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let any_key = add_any_source(&db, group);
        let other_vni_key = add_route(
            &db,
            MulticastRouteKey::any_source(group, other_vni).expect("key"),
        );
        let sg_key = add_route(
            &db,
            MulticastRouteKey::new(Some(source), other_group, vni())
                .expect("key"),
        );

        let imported = |q| keys(&db, q, MribTable::Imported);
        let sorted = |mut v: Vec<MulticastRouteKey>| {
            v.sort();
            v
        };

        assert_eq!(
            imported(query(Some(group), None, None)),
            sorted(vec![any_key, other_vni_key])
        );
        assert_eq!(
            imported(query(Some(group), None, Some(vni()))),
            vec![any_key]
        );
        assert_eq!(
            imported(query(None, None, Some(other_vni))),
            vec![other_vni_key]
        );
        assert_eq!(imported(query(None, Some(source), None)), vec![sg_key]);
        assert!(imported(query(Some(group), Some(source), None)).is_empty());
        assert_eq!(
            imported(query(None, None, Some(vni()))),
            sorted(vec![any_key, sg_key])
        );
    }

    #[test]
    fn query_rejects_impossible_combinations() {
        let v4_group =
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let v6_group = MulticastAddr::new_v6([0xff0e, 0, 0, 0, 0, 0, 0, 1])
            .expect("valid mcast");
        let v4_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v6_source =
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let mcast_source = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5));
        let v4 = Some(AddressFamily::Ipv4);
        let v6 = Some(AddressFamily::Ipv6);

        for (group, source, af) in [
            (Some(v6_group), None, v4),
            (None, Some(v4_source), v6),
            (Some(v4_group), Some(v6_source), None),
            (None, Some(mcast_source), None),
        ] {
            assert!(
                MribQuery::new(group, source, None, af, None).is_err(),
                "({group:?}, {source:?}, {af:?}) should be rejected"
            );
        }
        for (group, source, af) in [
            (Some(v4_group), Some(v4_source), v4),
            (None, Some(v6_source), v6),
            (Some(v6_group), None, None),
        ] {
            assert!(
                MribQuery::new(group, source, None, af, None).is_ok(),
                "({group:?}, {source:?}, {af:?}) should be accepted"
            );
        }
    }

    #[test]
    fn group_filter_reads_requested_table() {
        let (db, _log) = test_db("mrib_admin_tables");
        let any_group =
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let any_key = add_any_source(&db, any_group);

        let sg_group =
            MulticastAddr::new_v4(239, 2, 2, 2).expect("valid mcast");
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let sg_key = MulticastRouteKey::new(Some(source), sg_group, vni())
            .expect("valid key");
        db.add_static_mcast_routes(&[MulticastRoute::new(
            sg_key,
            underlay_group(),
            MulticastSourceProtocol::Static,
        )])
        .expect("add route");

        for table in [MribTable::Imported, MribTable::Selected] {
            assert_eq!(
                keys(&db, query(Some(any_group), None, Some(vni())), table),
                vec![any_key]
            );
        }

        let sg_query = || query(Some(sg_group), Some(source), Some(vni()));
        assert_eq!(keys(&db, sg_query(), MribTable::Imported), vec![sg_key]);
        assert!(keys(&db, sg_query(), MribTable::Selected).is_empty());

        let by_source = || query(None, Some(source), None);
        assert_eq!(keys(&db, by_source(), MribTable::Imported), vec![sg_key]);
        assert!(keys(&db, by_source(), MribTable::Selected).is_empty());

        let by_vni = || query(None, None, Some(vni()));
        assert_eq!(keys(&db, by_vni(), MribTable::Imported).len(), 2);
        assert_eq!(keys(&db, by_vni(), MribTable::Selected), vec![any_key]);

        let list = |table| keys(&db, query(None, None, None), table).len();
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

        for table in [MribTable::Imported, MribTable::Selected] {
            let list = |route_origin, address_family| {
                let q = MribQuery::new(
                    None,
                    None,
                    None,
                    address_family,
                    route_origin,
                )
                .expect("valid query");
                keys(&db, q, table).len()
            };
            assert_eq!(list(None, None), 1);
            assert_eq!(list(Some(RouteOriginFilter::Static), None), 1);
            assert_eq!(list(Some(RouteOriginFilter::Dynamic), None), 0);
            assert_eq!(list(None, Some(AddressFamily::Ipv4)), 1);
            assert_eq!(list(None, Some(AddressFamily::Ipv6)), 0);
        }
    }

    #[tokio::test]
    async fn http_static_route_lifecycle() {
        let server = TestServer::start("mrib_admin_http_lifecycle");
        let client = &server.client;
        let any_group =
            MulticastAddr::new_v4(239, 1, 1, 1).expect("valid mcast");
        let any_key =
            MulticastRouteKey::any_source(any_group, vni()).expect("key");
        let sg_group = MulticastAddr::new_v6([0xff0e, 0, 0, 0, 0, 0, 0, 1])
            .expect("mcast");
        let source = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let sg_key =
            MulticastRouteKey::new(Some(source), sg_group, vni()).expect("key");

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
            .get_mrib_imported(
                None,
                Some(&sg_group),
                None,
                Some(&source),
                Some(&vni()),
            )
            .await
            .expect("filter (S,G)")
            .into_inner();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, sg_key);

        let selected = client
            .get_mrib_selected(
                None,
                Some(&sg_group),
                None,
                Some(&source),
                Some(&vni()),
            )
            .await
            .expect("filter selected (S,G)")
            .into_inner();
        assert!(
            selected.is_empty(),
            "unreachable source should not be selected"
        );

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
        let removed = client
            .get_mrib_imported(None, Some(&any_group), None, None, None)
            .await
            .expect("filter removed group")
            .into_inner();
        assert!(removed.is_empty());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn http_rejects_invalid_requests() {
        let server = TestServer::start("mrib_admin_http_invalid");
        let client = &server.client;
        let get = http::Method::GET;

        for (query, want) in [
            ("group=10.0.0.1", 400),
            ("group=ff04::1", 400),
            ("group=239.1.1.1&vni=16777216", 400),
            ("group=239.1.1.1&source=2001:db8::1", 400),
            ("address_family=Ipv4&group=ff0e::1", 400),
            ("address_family=Ipv6&source=10.0.0.1", 400),
            ("source=224.0.0.5", 400),
            ("group=232.1.1.1", 200),
            ("group=239.1.1.1", 200),
            ("source=10.0.0.1", 200),
            ("vni=77", 200),
            ("address_family=Ipv4&group=239.1.1.1&source=10.0.0.1", 200),
        ] {
            let path = format!("/mrib/status/imported?{query}");
            assert_eq!(
                raw_status(client, get.clone(), &path, None).await,
                want,
                "{query}"
            );
        }

        let ssm_without_source = concat!(
            r#"{"routes":[{"key":{"V4":{"group":"232.1.1.1","source":null,"#,
            r#""vni":77}},"underlay_group":"ff04::1"}]}"#,
        );
        let bad_underlay = concat!(
            r#"{"routes":[{"key":{"V4":{"group":"239.1.1.1","source":null,"#,
            r#""vni":77}},"underlay_group":"ff05::1"}]}"#,
        );
        let missing_vni = concat!(
            r#"{"routes":[{"key":{"V4":{"group":"239.1.1.1","source":null}},"#,
            r#""underlay_group":"ff04::1"}]}"#,
        );
        for body in [ssm_without_source, bad_underlay, missing_vni] {
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
