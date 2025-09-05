//! This crate contains traits that decouple mg-lower from the underlying
//! platform. This is useful for testing mg-lower while not having to
//! have a running dpd, ddmd, or switch zone.
//!
//! TODO: maybe there can be lest boilerplate with Dropshot API traits?

use std::time::Duration;

use ddm_admin_client::Client as DdmClient;
use dpd_client::Client as DpdClient;
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

/// This trait wraps the dpd methods mg-lower uses.
pub(crate) trait Dpd {
    async fn route_ipv4_get(
        &self,
        cidr: &Ipv4Net,
    ) -> Result<
        dpd_client::ResponseValue<
            ::std::vec::Vec<dpd_client::types::Ipv4Route>,
        >,
        progenitor_client::Error<dpd_client::types::Error>,
    >;
    async fn route_ipv6_get(
        &self,
        cidr: &Ipv6Net,
    ) -> Result<
        dpd_client::ResponseValue<
            ::std::vec::Vec<dpd_client::types::Ipv6Route>,
        >,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn link_get(
        &self,
        port_id: &dpd_client::types::PortId,
        link_id: &dpd_client::types::LinkId,
    ) -> Result<
        dpd_client::ResponseValue<dpd_client::types::Link>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn loopback_ipv6_create(
        &self,
        addr: &dpd_client::types::Ipv6Entry,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn link_list_all<'a>(
        &'a self,
        filter: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<::std::vec::Vec<dpd_client::types::Link>>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn link_ipv4_list<'a>(
        &'a self,
        port_id: &'a dpd_client::types::PortId,
        link_id: &'a dpd_client::types::LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<dpd_client::types::Ipv4EntryResultsPage>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn link_ipv6_list<'a>(
        &'a self,
        port_id: &'a dpd_client::types::PortId,
        link_id: &'a dpd_client::types::LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<dpd_client::types::Ipv6EntryResultsPage>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    fn tag(&self) -> String;

    async fn route_ipv4_add<'a>(
        &'a self,
        body: &'a dpd_client::types::Ipv4RouteUpdate,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn route_ipv6_add<'a>(
        &'a self,
        body: &'a dpd_client::types::Ipv6RouteUpdate,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;

    async fn route_ipv4_delete_target<'a>(
        &'a self,
        cidr: &'a oxnet::Ipv4Net,
        port_id: &'a dpd_client::types::PortId,
        link_id: &'a dpd_client::types::LinkId,
        tgt_ip: &'a std::net::Ipv4Addr,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    >;
}

/// This trait wraps the ddmd methods mg-lower uses.
pub(crate) trait Ddm {
    async fn get_originated_tunnel_endpoints(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<
            Vec<ddm_admin_client::types::TunnelOrigin>,
        >,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    >;

    async fn get_originated(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<Vec<oxnet::Ipv6Net>>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    >;

    #[allow(clippy::ptr_arg)]
    async fn advertise_prefixes<'a>(
        &'a self,
        body: &'a Vec<oxnet::Ipv6Net>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    >;

    #[allow(clippy::ptr_arg)]
    async fn advertise_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<ddm_admin_client::types::TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    >;

    #[allow(clippy::ptr_arg)]
    async fn withdraw_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<ddm_admin_client::types::TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    >;
}

/// This trait wraps the methods that have expectations about switch zone
/// setup.
pub(crate) trait SwitchZone {
    fn get_route(
        &self,
        dst: IpNet,
        timeout: Option<Duration>,
    ) -> Result<libnet::route::Route, libnet::route::Error>;
}

/// Production dpd trait that simply passes through calls to a dpd client.
pub(crate) struct ProductionDpd {
    pub(crate) client: DpdClient,
}

impl Dpd for ProductionDpd {
    async fn route_ipv4_get(
        &self,
        cidr: &Ipv4Net,
    ) -> Result<
        dpd_client::ResponseValue<
            ::std::vec::Vec<dpd_client::types::Ipv4Route>,
        >,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.route_ipv4_get(cidr).await
    }

    async fn route_ipv6_get(
        &self,
        cidr: &Ipv6Net,
    ) -> Result<
        dpd_client::ResponseValue<
            ::std::vec::Vec<dpd_client::types::Ipv6Route>,
        >,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.route_ipv6_get(cidr).await
    }

    async fn link_get(
        &self,
        port_id: &dpd_client::types::PortId,
        link_id: &dpd_client::types::LinkId,
    ) -> Result<
        dpd_client::ResponseValue<dpd_client::types::Link>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.link_get(port_id, link_id).await
    }

    async fn loopback_ipv6_create(
        &self,
        addr: &dpd_client::types::Ipv6Entry,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.loopback_ipv6_create(addr).await
    }

    async fn link_list_all<'a>(
        &'a self,
        filter: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<::std::vec::Vec<dpd_client::types::Link>>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.link_list_all(filter).await
    }

    async fn link_ipv4_list<'a>(
        &'a self,
        port_id: &'a dpd_client::types::PortId,
        link_id: &'a dpd_client::types::LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<dpd_client::types::Ipv4EntryResultsPage>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client
            .link_ipv4_list(port_id, link_id, limit, page_token)
            .await
    }

    async fn link_ipv6_list<'a>(
        &'a self,
        port_id: &'a dpd_client::types::PortId,
        link_id: &'a dpd_client::types::LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<dpd_client::types::Ipv6EntryResultsPage>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client
            .link_ipv6_list(port_id, link_id, limit, page_token)
            .await
    }

    async fn route_ipv4_add<'a>(
        &'a self,
        body: &'a dpd_client::types::Ipv4RouteUpdate,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.route_ipv4_add(body).await
    }

    async fn route_ipv6_add<'a>(
        &'a self,
        body: &'a dpd_client::types::Ipv6RouteUpdate,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client.route_ipv6_add(body).await
    }

    async fn route_ipv4_delete_target<'a>(
        &'a self,
        cidr: &'a oxnet::Ipv4Net,
        port_id: &'a dpd_client::types::PortId,
        link_id: &'a dpd_client::types::LinkId,
        tgt_ip: &'a std::net::Ipv4Addr,
    ) -> Result<
        dpd_client::ResponseValue<()>,
        progenitor_client::Error<dpd_client::types::Error>,
    > {
        self.client
            .route_ipv4_delete_target(cidr, port_id, link_id, tgt_ip)
            .await
    }

    fn tag(&self) -> String {
        self.client.inner().tag.clone()
    }
}

/// Production ddm trait that simply passes through calls to a ddm client.
pub(crate) struct ProductionDdm {
    pub(crate) client: DdmClient,
}

impl Ddm for ProductionDdm {
    async fn get_originated_tunnel_endpoints(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<
            Vec<ddm_admin_client::types::TunnelOrigin>,
        >,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    > {
        self.client.get_originated_tunnel_endpoints().await
    }

    async fn get_originated(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<Vec<oxnet::Ipv6Net>>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    > {
        self.client.get_originated().await
    }

    async fn advertise_prefixes<'a>(
        &'a self,
        body: &'a Vec<oxnet::Ipv6Net>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    > {
        self.client.advertise_prefixes(body).await
    }

    async fn advertise_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<ddm_admin_client::types::TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    > {
        self.client.advertise_tunnel_endpoints(body).await
    }

    async fn withdraw_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<ddm_admin_client::types::TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<ddm_admin_client::types::Error>,
    > {
        self.client.withdraw_tunnel_endpoints(body).await
    }
}

/// Production dpd trait that simply passes through calls to underlying os
/// interfaces such as libnet.
pub(crate) struct ProductionSwitchZone {}

impl SwitchZone for ProductionSwitchZone {
    fn get_route(
        &self,
        dst: IpNet,
        timeout: Option<Duration>,
    ) -> Result<libnet::route::Route, libnet::route::Error> {
        libnet::get_route(dst, timeout)
    }
}

/// This module contains platform trait implementations for testing.
#[cfg(test)]
pub(crate) mod test {
    use std::{collections::HashMap, net::IpAddr};

    use dpd_client::types::Ipv6Entry;
    use std::sync::Mutex;

    use super::*;

    // helper macros for forming dropshot responses
    macro_rules! dpd_response_ok {
        ($x:expr) => {
            dpd_client::ResponseValue::new(
                $x,
                reqwest::StatusCode::OK,
                reqwest::header::HeaderMap::default(),
            )
        };
    }
    macro_rules! ddm_response_ok {
        ($x:expr) => {
            ddm_admin_client::ResponseValue::new(
                $x,
                reqwest::StatusCode::OK,
                reqwest::header::HeaderMap::default(),
            )
        };
    }

    /// A stateful mock dpd implementation. Carries just enough state to be
    /// useful for tests.
    pub(crate) struct TestDpd {
        pub(crate) links: Mutex<Vec<dpd_client::types::Link>>,
        pub(crate) v4_routes:
            Mutex<HashMap<Ipv4Net, Vec<dpd_client::types::Ipv4Route>>>,
        pub(crate) v6_routes:
            Mutex<HashMap<Ipv6Net, Vec<dpd_client::types::Ipv6Route>>>,
        pub(crate) v4_addrs: HashMap<String, Vec<dpd_client::types::Ipv4Entry>>,
        pub(crate) v6_addrs: HashMap<String, Vec<dpd_client::types::Ipv6Entry>>,
        pub(crate) loopback: Mutex<Option<Ipv6Entry>>,
    }

    impl Default for TestDpd {
        fn default() -> Self {
            Self {
                links: Mutex::new(Vec::default()),
                v4_routes: Mutex::new(HashMap::default()),
                v6_routes: Mutex::new(HashMap::default()),
                v4_addrs: HashMap::default(),
                v6_addrs: HashMap::default(),
                loopback: Mutex::new(None),
            }
        }
    }

    impl Dpd for TestDpd {
        async fn link_get(
            &self,
            port_id: &dpd_client::types::PortId,
            link_id: &dpd_client::types::LinkId,
        ) -> Result<
            dpd_client::ResponseValue<dpd_client::types::Link>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let links = self.links.lock().unwrap();
            let link = links
                .iter()
                .find(|x| &x.port_id == port_id && &x.link_id == link_id);

            match link {
                Some(l) => Ok(dpd_response_ok!(l.clone())),
                None => todo!("dpd errors for link get"),
            }
        }

        async fn route_ipv4_get(
            &self,
            cidr: &Ipv4Net,
        ) -> Result<
            dpd_client::ResponseValue<
                ::std::vec::Vec<dpd_client::types::Ipv4Route>,
            >,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let result = self
                .v4_routes
                .lock()
                .unwrap()
                .get(cidr)
                .cloned()
                .unwrap_or(Vec::default());
            Ok(dpd_response_ok!(result))
        }

        async fn route_ipv6_get(
            &self,
            cidr: &Ipv6Net,
        ) -> Result<
            dpd_client::ResponseValue<
                ::std::vec::Vec<dpd_client::types::Ipv6Route>,
            >,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let result = self
                .v6_routes
                .lock()
                .unwrap()
                .get(cidr)
                .cloned()
                .unwrap_or(Vec::default());
            Ok(dpd_response_ok!(result))
        }

        async fn loopback_ipv6_create(
            &self,
            addr: &dpd_client::types::Ipv6Entry,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            self.loopback.lock().unwrap().replace(addr.clone());
            Ok(dpd_response_ok!(()))
        }

        async fn link_list_all<'a>(
            &'a self,
            filter: Option<&'a str>,
        ) -> Result<
            dpd_client::ResponseValue<::std::vec::Vec<dpd_client::types::Link>>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let links = self.links.lock().unwrap();
            let result = links
                .iter()
                .filter(|x| match filter {
                    Some(f) => x.to_string().contains(f),
                    None => true,
                })
                .cloned()
                .collect();
            Ok(dpd_response_ok!(result))
        }

        async fn link_ipv4_list<'a>(
            &'a self,
            port_id: &'a dpd_client::types::PortId,
            link_id: &'a dpd_client::types::LinkId,
            _limit: Option<std::num::NonZeroU32>,
            _page_token: Option<&'a str>,
        ) -> Result<
            dpd_client::ResponseValue<dpd_client::types::Ipv4EntryResultsPage>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let lnk = self.link_get(port_id, link_id).await?.into_inner();
            let addrs = self
                .v4_addrs
                .get(&lnk.to_string())
                .cloned()
                .unwrap_or_default();

            Ok(dpd_response_ok!(dpd_client::types::Ipv4EntryResultsPage {
                items: addrs,
                next_page: None,
            }))
        }

        async fn link_ipv6_list<'a>(
            &'a self,
            port_id: &'a dpd_client::types::PortId,
            link_id: &'a dpd_client::types::LinkId,
            _limit: Option<std::num::NonZeroU32>,
            _page_token: Option<&'a str>,
        ) -> Result<
            dpd_client::ResponseValue<dpd_client::types::Ipv6EntryResultsPage>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let lnk = self.link_get(port_id, link_id).await?.into_inner();
            let addrs = self
                .v6_addrs
                .get(&lnk.to_string())
                .cloned()
                .unwrap_or_default();

            Ok(dpd_response_ok!(dpd_client::types::Ipv6EntryResultsPage {
                items: addrs,
                next_page: None,
            }))
        }

        async fn route_ipv4_add<'a>(
            &'a self,
            body: &'a dpd_client::types::Ipv4RouteUpdate,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let mut routes = self.v4_routes.lock().unwrap();
            match routes.get_mut(&body.cidr) {
                Some(targets) => {
                    targets.push(body.target.clone());
                }
                None => {
                    routes.insert(body.cidr, vec![body.target.clone()]);
                }
            }
            Ok(dpd_response_ok!(()))
        }

        async fn route_ipv6_add<'a>(
            &'a self,
            body: &'a dpd_client::types::Ipv6RouteUpdate,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let mut routes = self.v6_routes.lock().unwrap();
            match routes.get_mut(&body.cidr) {
                Some(targets) => {
                    targets.push(body.target.clone());
                }
                None => {
                    routes.insert(body.cidr, vec![body.target.clone()]);
                }
            }
            Ok(dpd_response_ok!(()))
        }

        async fn route_ipv4_delete_target<'a>(
            &'a self,
            cidr: &'a oxnet::Ipv4Net,
            port_id: &'a dpd_client::types::PortId,
            link_id: &'a dpd_client::types::LinkId,
            tgt_ip: &'a std::net::Ipv4Addr,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<dpd_client::types::Error>,
        > {
            let mut routes = self.v4_routes.lock().unwrap();
            if let Some(targets) = routes.get_mut(cidr) {
                targets.retain(|x| {
                    !(x.tgt_ip == *tgt_ip
                        && x.link_id == *link_id
                        && x.port_id == *port_id)
                });
            }
            routes.retain(|_, v| !v.is_empty());
            Ok(dpd_response_ok!(()))
        }

        fn tag(&self) -> String {
            String::from("mg_lower_test")
        }
    }

    /// A stateful mock ddm implementation. Carries just enough state to be
    /// useful for tests.
    pub(crate) struct TestDdm {
        pub(crate) tunnel_originated:
            Mutex<Vec<ddm_admin_client::types::TunnelOrigin>>,
        pub(crate) originated: Mutex<Vec<oxnet::Ipv6Net>>,
    }

    impl Default for TestDdm {
        fn default() -> Self {
            Self {
                tunnel_originated: Mutex::new(Vec::default()),
                originated: Mutex::new(Vec::default()),
            }
        }
    }

    impl Ddm for TestDdm {
        async fn get_originated_tunnel_endpoints(
            &self,
        ) -> Result<
            ddm_admin_client::ResponseValue<
                Vec<ddm_admin_client::types::TunnelOrigin>,
            >,
            progenitor_client::Error<ddm_admin_client::types::Error>,
        > {
            Ok(ddm_response_ok!(self
                .tunnel_originated
                .lock()
                .unwrap()
                .clone()))
        }

        async fn get_originated(
            &self,
        ) -> Result<
            ddm_admin_client::ResponseValue<Vec<oxnet::Ipv6Net>>,
            progenitor_client::Error<ddm_admin_client::types::Error>,
        > {
            Ok(ddm_response_ok!(self.originated.lock().unwrap().clone()))
        }

        async fn advertise_prefixes<'a>(
            &'a self,
            body: &'a Vec<oxnet::Ipv6Net>,
        ) -> Result<
            ddm_admin_client::ResponseValue<()>,
            progenitor_client::Error<ddm_admin_client::types::Error>,
        > {
            self.originated.lock().unwrap().extend(body);
            Ok(ddm_response_ok!(()))
        }

        async fn advertise_tunnel_endpoints<'a>(
            &'a self,
            body: &'a Vec<ddm_admin_client::types::TunnelOrigin>,
        ) -> Result<
            ddm_admin_client::ResponseValue<()>,
            progenitor_client::Error<ddm_admin_client::types::Error>,
        > {
            self.tunnel_originated.lock().unwrap().extend(body.clone());
            Ok(ddm_response_ok!(()))
        }

        async fn withdraw_tunnel_endpoints<'a>(
            &'a self,
            body: &'a Vec<ddm_admin_client::types::TunnelOrigin>,
        ) -> Result<
            ddm_admin_client::ResponseValue<()>,
            progenitor_client::Error<ddm_admin_client::types::Error>,
        > {
            self.tunnel_originated
                .lock()
                .unwrap()
                .retain(|x| !body.contains(x));
            Ok(ddm_response_ok!(()))
        }
    }

    /// A mock swtich zone implementation.
    pub(crate) struct TestSwitchZone {
        pub(crate) routes: HashMap<IpNet, (Option<String>, IpAddr)>,
        pub(crate) default_ifname: Option<String>,
        pub(crate) default_gw: IpAddr,
    }
    impl SwitchZone for TestSwitchZone {
        fn get_route(
            &self,
            dst: IpNet,
            _timeout: Option<Duration>,
        ) -> Result<libnet::route::Route, libnet::route::Error> {
            let rt = self.routes.get(&dst);
            Ok(libnet::route::Route {
                dest: dst.addr(),
                mask: dst.width().into(),
                gw: rt.map(|x| x.1).unwrap_or(self.default_gw),
                delay: 0,
                ifx: rt
                    .map(|x| x.0.clone())
                    .unwrap_or(self.default_ifname.clone()),
            })
        }
    }
}
