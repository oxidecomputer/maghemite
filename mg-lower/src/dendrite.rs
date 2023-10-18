use crate::Error;
use crate::MG_LOWER_TAG;
use dpd_client::types::PortId;
use dpd_client::Client as DpdClient;
use libnet::{get_route, IpPrefix, Ipv4Prefix};
use rdb::Route4ImportKey;
use slog::{error, Logger};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;

const TFPORT_QSFP_DEVICE_PREFIX: &str = "tfportqsfp";
const DPD_QSFP_DPORT_PREFIX: &str = "qsfp";

/// A wrapper around Dendrite routes so we can perform set functions over them.
pub(crate) struct RouteHash(pub(crate) dpd_client::types::Route);

impl Hash for RouteHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.cidr.hash(state);
        self.0.nexthop.hash(state);
    }
}

impl PartialEq for RouteHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.cidr == other.0.cidr && self.0.nexthop == other.0.nexthop
    }
}

impl Eq for RouteHash {}

/// Perform a set of route additions and deletions via the Dendrite API.
pub(crate) fn update_dendrite<'a, I>(
    to_add: I,
    to_del: I,
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) -> Result<(), Error>
where
    I: Iterator<Item = &'a RouteHash>,
{
    for r in to_add {
        if let Err(e) = rt.block_on(async { dpd.route_ipv4_create(&r.0).await })
        {
            error!(log, "failed to create route {:?}: {}", r.0, e);
            Err(e)?;
        }
    }
    for r in to_del {
        let cidr = match r.0.cidr {
            dpd_client::Cidr::V4(cidr) => cidr,
            _ => continue,
        };
        if let Err(e) =
            rt.block_on(async { dpd.route_ipv4_delete(&cidr).await })
        {
            error!(log, "failed to create route {:?}: {}", r.0, e);
            Err(e)?;
        }
    }
    Ok(())
}

/// Translate a RIB route data structure to a Dendrite route.
pub(crate) fn db_route_to_dendrite_route(
    rs: Vec<Route4ImportKey>,
    log: &Logger,
    _dpd: &DpdClient,
) -> Vec<dpd_client::types::Route> {
    let mut result = Vec::new();

    for r in &rs {
        let sys_route = match get_route(IpPrefix::V4(Ipv4Prefix {
            addr: r.nexthop,
            mask: 32,
        })) {
            Ok(r) => r,
            Err(e) => {
                error!(log, "Unable to get route for {:?}: {}", r, e);
                continue;
            }
        };

        let ifname = match sys_route.ifx {
            Some(name) => name,
            None => {
                error!(
                    log,
                    "No interface associated with route for {:?}: {:?}",
                    r,
                    sys_route,
                );
                continue;
            }
        };

        // TODO this is gross, use link type properties rather than futzing
        // around with strings.
        let Some(egress_port_num) = ifname
            .strip_prefix(TFPORT_QSFP_DEVICE_PREFIX)
            .and_then(|x| x.strip_suffix("_0"))
            .map(|x| x.trim())
            .and_then(|x| x.parse::<usize>().ok())
        else {
            error!(
                log,
                "expected {}$M_0, got {}", TFPORT_QSFP_DEVICE_PREFIX, ifname
            );
            continue;
        };

        let switch_port = match PortId::from_str(&format!(
            "{}{}",
            DPD_QSFP_DPORT_PREFIX, egress_port_num
        )) {
            Ok(swp) => swp,
            Err(e) => {
                error!(log, "bad port name: {e}");
                continue;
            }
        };

        // TODO breakout considerations
        let link = dpd_client::types::LinkId(0);

        result.push(dpd_client::types::Route {
            tag: MG_LOWER_TAG.into(),
            cidr: dpd_client::Cidr::V4(dpd_client::Ipv4Cidr {
                prefix: r.prefix.value,
                prefix_len: r.prefix.length,
            }),
            switch_port,
            link,
            nexthop: r.nexthop.into(),
            vid: None,
        });
    }

    result
}

/// Create a new Dendrite/dpd client. The lower half always runs on the same
/// host/zone as the underlying platform.
pub(crate) fn new_dpd_client(log: &Logger) -> DpdClient {
    let client_state = dpd_client::ClientState {
        tag: MG_LOWER_TAG.into(),
        log: log.clone(),
    };
    DpdClient::new(
        &format!("http://localhost:{}", dpd_client::default_port()),
        client_state,
    )
}
