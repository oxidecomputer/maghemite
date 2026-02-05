//! This crate contains traits that decouple mg-lower from the underlying
//! platform. This is useful for testing mg-lower while not having to
//! have a running dpd, ddmd, or switch zone.
//!
//! TODO: maybe there can be less boilerplate with Dropshot API traits?

use std::net::IpAddr;
use std::time::Duration;

use ddm_admin_client::types::{Error as DdmError, *};
use dpd_client::types::{Error as DpdError, *};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};
#[cfg(target_os = "illumos")]
use {
    ddm_admin_client::Client as DdmClient, dpd_client::Client as DpdClient,
    dpd_client::ClientInfo,
};

/// Platform-agnostic route representation mirroring `libnet::route::Route`.
///
/// This allows the `SwitchZone` trait and test mocks to compile on platforms
/// where `libnet` is not available (e.g. macOS).
#[derive(Debug)]
pub struct SysRoute {
    pub dest: IpAddr,
    pub mask: u32,
    pub gw: IpAddr,
    pub delay: u32,
    pub ifx: Option<String>,
}

/// Platform-agnostic route error mirroring `libnet::route::Error`.
#[derive(thiserror::Error, Debug)]
pub enum SysRouteError {
    #[error("{0} not implemented")]
    NotImplemented(String),
    #[error("system error {0}")]
    SystemError(String),
    #[error("bad argument: {0}")]
    BadArgument(String),
    #[error("exists")]
    Exists,
    #[error("route does not exist")]
    DoesNotExist,
    #[error("insufficient resources")]
    InsufficientResources,
    #[error("insufficient permissions")]
    InsufficientPermissions,
    #[error("io error {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(target_os = "illumos")]
impl From<libnet::route::Error> for SysRouteError {
    fn from(e: libnet::route::Error) -> Self {
        match e {
            libnet::route::Error::NotImplemented(s) => {
                SysRouteError::NotImplemented(s)
            }
            libnet::route::Error::SystemError(s) => {
                SysRouteError::SystemError(s)
            }
            libnet::route::Error::BadArgument(s) => {
                SysRouteError::BadArgument(s)
            }
            libnet::route::Error::Exists => SysRouteError::Exists,
            libnet::route::Error::DoesNotExist => SysRouteError::DoesNotExist,
            libnet::route::Error::InsufficientResources => {
                SysRouteError::InsufficientResources
            }
            libnet::route::Error::InsufficientPermissions => {
                SysRouteError::InsufficientPermissions
            }
            libnet::route::Error::IoError(e) => SysRouteError::IoError(e),
        }
    }
}

#[cfg(target_os = "illumos")]
impl From<libnet::route::Route> for SysRoute {
    fn from(r: libnet::route::Route) -> Self {
        SysRoute {
            dest: r.dest,
            mask: r.mask,
            gw: r.gw,
            delay: r.delay,
            ifx: r.ifx,
        }
    }
}

/// This trait wraps the dpd methods mg-lower uses.
#[allow(async_fn_in_trait)]
pub trait Dpd {
    async fn route_ipv4_get(
        &self,
        cidr: &Ipv4Net,
    ) -> Result<
        dpd_client::ResponseValue<Vec<Route>>,
        progenitor_client::Error<DpdError>,
    >;
    async fn route_ipv6_get(
        &self,
        cidr: &Ipv6Net,
    ) -> Result<
        dpd_client::ResponseValue<Vec<Ipv6Route>>,
        progenitor_client::Error<DpdError>,
    >;
    async fn link_get(
        &self,
        port_id: &PortId,
        link_id: &LinkId,
    ) -> Result<
        dpd_client::ResponseValue<Link>,
        progenitor_client::Error<DpdError>,
    >;
    async fn loopback_ipv6_create(
        &self,
        addr: &Ipv6Entry,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>;

    async fn link_list_all<'a>(
        &'a self,
        filter: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<Vec<Link>>,
        progenitor_client::Error<DpdError>,
    >;

    async fn link_ipv4_list<'a>(
        &'a self,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<Ipv4EntryResultsPage>,
        progenitor_client::Error<DpdError>,
    >;

    async fn link_ipv6_list<'a>(
        &'a self,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<Ipv6EntryResultsPage>,
        progenitor_client::Error<DpdError>,
    >;

    fn tag(&self) -> String;

    async fn route_ipv4_add<'a>(
        &'a self,
        body: &'a Ipv4RouteUpdateV2,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>;

    async fn route_ipv6_add<'a>(
        &'a self,
        body: &'a Ipv6RouteUpdate,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>;

    async fn route_ipv4_delete_target<'a>(
        &'a self,
        cidr: &'a oxnet::Ipv4Net,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        tgt_ip: &'a IpAddr,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>;

    async fn route_ipv6_delete_target<'a>(
        &'a self,
        cidr: &'a oxnet::Ipv6Net,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        tgt_ip: &'a std::net::Ipv6Addr,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>;
}

/// This trait wraps the ddmd methods mg-lower uses.
#[allow(async_fn_in_trait)]
pub trait Ddm {
    async fn get_originated_tunnel_endpoints(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<Vec<TunnelOrigin>>,
        progenitor_client::Error<DdmError>,
    >;

    async fn get_originated(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<Vec<oxnet::Ipv6Net>>,
        progenitor_client::Error<DdmError>,
    >;

    #[allow(clippy::ptr_arg)]
    async fn advertise_prefixes<'a>(
        &'a self,
        body: &'a Vec<oxnet::Ipv6Net>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<DdmError>,
    >;

    #[allow(clippy::ptr_arg)]
    async fn advertise_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<DdmError>,
    >;

    #[allow(clippy::ptr_arg)]
    async fn withdraw_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<DdmError>,
    >;
}

/// This trait wraps the methods that have expectations about switch zone
/// setup.
pub trait SwitchZone {
    fn get_route(
        &self,
        dst: IpNet,
        timeout: Option<Duration>,
    ) -> Result<SysRoute, SysRouteError>;
}

/// Production dpd trait that simply passes through calls to a dpd client.
#[cfg(target_os = "illumos")]
pub struct ProductionDpd {
    pub client: DpdClient,
}

#[cfg(target_os = "illumos")]
impl Dpd for ProductionDpd {
    async fn route_ipv4_get(
        &self,
        cidr: &Ipv4Net,
    ) -> Result<
        dpd_client::ResponseValue<Vec<Route>>,
        progenitor_client::Error<DpdError>,
    > {
        self.client.route_ipv4_get(cidr).await
    }

    async fn route_ipv6_get(
        &self,
        cidr: &Ipv6Net,
    ) -> Result<
        dpd_client::ResponseValue<Vec<Ipv6Route>>,
        progenitor_client::Error<DpdError>,
    > {
        self.client.route_ipv6_get(cidr).await
    }

    async fn link_get(
        &self,
        port_id: &PortId,
        link_id: &LinkId,
    ) -> Result<
        dpd_client::ResponseValue<Link>,
        progenitor_client::Error<DpdError>,
    > {
        self.client.link_get(port_id, link_id).await
    }

    async fn loopback_ipv6_create(
        &self,
        addr: &Ipv6Entry,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>
    {
        self.client.loopback_ipv6_create(addr).await
    }

    async fn link_list_all<'a>(
        &'a self,
        filter: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<Vec<Link>>,
        progenitor_client::Error<DpdError>,
    > {
        self.client.link_list_all(filter).await
    }

    async fn link_ipv4_list<'a>(
        &'a self,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<Ipv4EntryResultsPage>,
        progenitor_client::Error<DpdError>,
    > {
        self.client
            .link_ipv4_list(port_id, link_id, limit, page_token)
            .await
    }

    async fn link_ipv6_list<'a>(
        &'a self,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        limit: Option<std::num::NonZeroU32>,
        page_token: Option<&'a str>,
    ) -> Result<
        dpd_client::ResponseValue<Ipv6EntryResultsPage>,
        progenitor_client::Error<DpdError>,
    > {
        self.client
            .link_ipv6_list(port_id, link_id, limit, page_token)
            .await
    }

    async fn route_ipv4_add<'a>(
        &'a self,
        body: &'a Ipv4RouteUpdateV2,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>
    {
        self.client.route_ipv4_add(body).await
    }

    async fn route_ipv6_add<'a>(
        &'a self,
        body: &'a Ipv6RouteUpdate,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>
    {
        self.client.route_ipv6_add(body).await
    }

    async fn route_ipv4_delete_target<'a>(
        &'a self,
        cidr: &'a oxnet::Ipv4Net,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        tgt_ip: &'a IpAddr,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>
    {
        self.client
            .route_ipv4_delete_target(cidr, port_id, link_id, tgt_ip)
            .await
    }

    async fn route_ipv6_delete_target<'a>(
        &'a self,
        cidr: &'a oxnet::Ipv6Net,
        port_id: &'a PortId,
        link_id: &'a LinkId,
        tgt_ip: &'a std::net::Ipv6Addr,
    ) -> Result<dpd_client::ResponseValue<()>, progenitor_client::Error<DpdError>>
    {
        self.client
            .route_ipv6_delete_target(cidr, port_id, link_id, tgt_ip)
            .await
    }

    fn tag(&self) -> String {
        self.client.inner().tag.clone()
    }
}

/// Production ddm trait that simply passes through calls to a ddm client.
#[cfg(target_os = "illumos")]
pub struct ProductionDdm {
    pub client: DdmClient,
}

#[cfg(target_os = "illumos")]
impl Ddm for ProductionDdm {
    async fn get_originated_tunnel_endpoints(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<Vec<TunnelOrigin>>,
        progenitor_client::Error<DdmError>,
    > {
        self.client.get_originated_tunnel_endpoints().await
    }

    async fn get_originated(
        &self,
    ) -> Result<
        ddm_admin_client::ResponseValue<Vec<oxnet::Ipv6Net>>,
        progenitor_client::Error<DdmError>,
    > {
        self.client.get_originated().await
    }

    async fn advertise_prefixes<'a>(
        &'a self,
        body: &'a Vec<oxnet::Ipv6Net>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<DdmError>,
    > {
        self.client.advertise_prefixes(body).await
    }

    async fn advertise_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<DdmError>,
    > {
        self.client.advertise_tunnel_endpoints(body).await
    }

    async fn withdraw_tunnel_endpoints<'a>(
        &'a self,
        body: &'a Vec<TunnelOrigin>,
    ) -> Result<
        ddm_admin_client::ResponseValue<()>,
        progenitor_client::Error<DdmError>,
    > {
        self.client.withdraw_tunnel_endpoints(body).await
    }
}

/// Production switch zone that uses libnet for route lookups (illumos only).
#[cfg(target_os = "illumos")]
pub struct ProductionSwitchZone {}

#[cfg(target_os = "illumos")]
impl SwitchZone for ProductionSwitchZone {
    fn get_route(
        &self,
        dst: IpNet,
        timeout: Option<Duration>,
    ) -> Result<SysRoute, SysRouteError> {
        libnet::get_route(dst, timeout)
            .map(SysRoute::from)
            .map_err(SysRouteError::from)
    }
}

/// This module contains platform trait implementations for testing.
#[cfg(test)]
pub(crate) mod test {
    use crate::MG_LOWER_TAG;

    use super::*;
    use std::sync::Mutex;
    use std::{collections::HashMap, net::IpAddr};

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
        pub(crate) links: Mutex<Vec<Link>>,
        pub(crate) v4_routes: Mutex<HashMap<Ipv4Net, Vec<Route>>>,
        pub(crate) v6_routes: Mutex<HashMap<Ipv6Net, Vec<Ipv6Route>>>,
        pub(crate) v4_addrs: HashMap<String, Vec<Ipv4Entry>>,
        pub(crate) v6_addrs: HashMap<String, Vec<Ipv6Entry>>,
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
            port_id: &PortId,
            link_id: &LinkId,
        ) -> Result<
            dpd_client::ResponseValue<Link>,
            progenitor_client::Error<DpdError>,
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
            dpd_client::ResponseValue<Vec<Route>>,
            progenitor_client::Error<DpdError>,
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
            dpd_client::ResponseValue<Vec<Ipv6Route>>,
            progenitor_client::Error<DpdError>,
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
            addr: &Ipv6Entry,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<DpdError>,
        > {
            self.loopback.lock().unwrap().replace(addr.clone());
            Ok(dpd_response_ok!(()))
        }

        async fn link_list_all<'a>(
            &'a self,
            filter: Option<&'a str>,
        ) -> Result<
            dpd_client::ResponseValue<Vec<Link>>,
            progenitor_client::Error<DpdError>,
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
            port_id: &'a PortId,
            link_id: &'a LinkId,
            _limit: Option<std::num::NonZeroU32>,
            _page_token: Option<&'a str>,
        ) -> Result<
            dpd_client::ResponseValue<Ipv4EntryResultsPage>,
            progenitor_client::Error<DpdError>,
        > {
            let lnk = self.link_get(port_id, link_id).await?.into_inner();
            let addrs = self
                .v4_addrs
                .get(&lnk.to_string())
                .cloned()
                .unwrap_or_default();

            Ok(dpd_response_ok!(Ipv4EntryResultsPage {
                items: addrs,
                next_page: None,
            }))
        }

        async fn link_ipv6_list<'a>(
            &'a self,
            port_id: &'a PortId,
            link_id: &'a LinkId,
            _limit: Option<std::num::NonZeroU32>,
            _page_token: Option<&'a str>,
        ) -> Result<
            dpd_client::ResponseValue<Ipv6EntryResultsPage>,
            progenitor_client::Error<DpdError>,
        > {
            let lnk = self.link_get(port_id, link_id).await?.into_inner();
            let addrs = self
                .v6_addrs
                .get(&lnk.to_string())
                .cloned()
                .unwrap_or_default();

            Ok(dpd_response_ok!(Ipv6EntryResultsPage {
                items: addrs,
                next_page: None,
            }))
        }

        async fn route_ipv4_add<'a>(
            &'a self,
            body: &'a Ipv4RouteUpdateV2,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<DpdError>,
        > {
            let route = match &body.target {
                RouteTarget::V4(v4) => Route::V4(v4.clone()),
                RouteTarget::V6(v6) => Route::V6(v6.clone()),
            };
            let mut routes = self.v4_routes.lock().unwrap();
            match routes.get_mut(&body.cidr) {
                Some(targets) => {
                    targets.push(route);
                }
                None => {
                    routes.insert(body.cidr, vec![route]);
                }
            }
            Ok(dpd_response_ok!(()))
        }

        async fn route_ipv6_add<'a>(
            &'a self,
            body: &'a Ipv6RouteUpdate,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<DpdError>,
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
            port_id: &'a PortId,
            link_id: &'a LinkId,
            tgt_ip: &'a IpAddr,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<DpdError>,
        > {
            let mut routes = self.v4_routes.lock().unwrap();
            if let Some(targets) = routes.get_mut(cidr) {
                targets.retain(|x| match (x, tgt_ip) {
                    (Route::V4(x), IpAddr::V4(ip)) => {
                        !(x.tgt_ip == *ip
                            && x.link_id == *link_id
                            && x.port_id == *port_id)
                    }
                    (Route::V6(x), IpAddr::V6(ip)) => {
                        !(x.tgt_ip == *ip
                            && x.link_id == *link_id
                            && x.port_id == *port_id)
                    }
                    _ => true,
                });
            }
            routes.retain(|_, v| !v.is_empty());
            Ok(dpd_response_ok!(()))
        }

        async fn route_ipv6_delete_target<'a>(
            &'a self,
            cidr: &'a oxnet::Ipv6Net,
            port_id: &'a PortId,
            link_id: &'a LinkId,
            tgt_ip: &'a std::net::Ipv6Addr,
        ) -> Result<
            dpd_client::ResponseValue<()>,
            progenitor_client::Error<DpdError>,
        > {
            let mut routes = self.v6_routes.lock().unwrap();
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
            String::from(MG_LOWER_TAG)
        }
    }

    /// A stateful mock ddm implementation. Carries just enough state to be
    /// useful for tests.
    pub(crate) struct TestDdm {
        pub(crate) tunnel_originated: Mutex<Vec<TunnelOrigin>>,
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
            ddm_admin_client::ResponseValue<Vec<TunnelOrigin>>,
            progenitor_client::Error<DdmError>,
        > {
            Ok(ddm_response_ok!(
                self.tunnel_originated.lock().unwrap().clone()
            ))
        }

        async fn get_originated(
            &self,
        ) -> Result<
            ddm_admin_client::ResponseValue<Vec<oxnet::Ipv6Net>>,
            progenitor_client::Error<DdmError>,
        > {
            Ok(ddm_response_ok!(self.originated.lock().unwrap().clone()))
        }

        async fn advertise_prefixes<'a>(
            &'a self,
            body: &'a Vec<oxnet::Ipv6Net>,
        ) -> Result<
            ddm_admin_client::ResponseValue<()>,
            progenitor_client::Error<DdmError>,
        > {
            self.originated.lock().unwrap().extend(body);
            Ok(ddm_response_ok!(()))
        }

        async fn advertise_tunnel_endpoints<'a>(
            &'a self,
            body: &'a Vec<TunnelOrigin>,
        ) -> Result<
            ddm_admin_client::ResponseValue<()>,
            progenitor_client::Error<DdmError>,
        > {
            self.tunnel_originated.lock().unwrap().extend(body.clone());
            Ok(ddm_response_ok!(()))
        }

        async fn withdraw_tunnel_endpoints<'a>(
            &'a self,
            body: &'a Vec<TunnelOrigin>,
        ) -> Result<
            ddm_admin_client::ResponseValue<()>,
            progenitor_client::Error<DdmError>,
        > {
            self.tunnel_originated
                .lock()
                .unwrap()
                .retain(|x| !body.contains(x));
            Ok(ddm_response_ok!(()))
        }
    }

    /// A mock switch zone implementation.
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
        ) -> Result<SysRoute, SysRouteError> {
            let rt = self.routes.get(&dst);
            Ok(SysRoute {
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
