use dpd_client::types::PortId;
use dpd_client::Client as DpdClient;
use libnet::{get_route, IpPrefix, Ipv4Prefix};
use rdb::{ChangeSet, Db, Route4ImportKey};
use slog::{error, Logger};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::mpsc::channel;
use std::sync::Arc;

const MG_LOWER_DPD_TAG: &str = "mg-lower";

pub fn run(db: Db, log: Logger, rt: Arc<tokio::runtime::Handle>) {
    let (tx, rx) = channel();

    // start the db watcher first so we catch any changes that may occur while
    // we're initializing
    db.watch(tx);

    // initialize the underlying router with the current state
    let dpd = new_dpd_client(&log);
    let mut generation = initialize(&db, &log, &dpd, rt.clone());

    // handle any changes that occur
    loop {
        match rx.recv() {
            Ok(change) => {
                generation = handle_change(
                    &db,
                    change,
                    &log,
                    &dpd,
                    generation,
                    rt.clone(),
                );
            }
            Err(e) => {
                error!(log, "mg-lower watch rx: {e}");
            }
        }
    }
}

struct RouteHash(dpd_client::types::Route);

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

fn initialize(
    db: &Db,
    log: &Logger,
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
) -> u64 {
    let generation = db.generation();

    // get all imported routes from db
    let imported: HashSet<RouteHash> =
        db_route_to_dendrite_route(db.get_imported4(), log, dpd)
            .iter()
            .map(|x| RouteHash(x.clone()))
            .collect();

    // get all routes created by mg-lower from dendrite
    let active: HashSet<RouteHash> = rt
        .block_on(async { dpd.route_ipv4_list(None, None).await })
        .unwrap()
        .items
        .iter()
        .filter(|x| x.tag == MG_LOWER_DPD_TAG)
        .map(|x| RouteHash(x.clone()))
        .collect();

    // determine what routes need to be added and deleted
    let to_add = imported.difference(&active);
    let to_del = active.difference(&imported);

    update_dendrite(to_add, to_del, dpd, rt, log);

    generation
}

fn update_dendrite<'a, I>(
    to_add: I,
    to_del: I,
    dpd: &DpdClient,
    rt: Arc<tokio::runtime::Handle>,
    log: &Logger,
) where
    I: Iterator<Item = &'a RouteHash>,
{
    for r in to_add {
        if let Err(e) = rt.block_on(async { dpd.route_ipv4_create(&r.0).await })
        {
            error!(log, "failed to create route {:?}: {}", r.0, e);
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
        }
    }
}

fn db_route_to_dendrite_route(
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
            .strip_prefix("tfportqsfp")
            .and_then(|x| x.strip_suffix("_0"))
            .map(|x| x.trim())
            .and_then(|x| x.parse::<usize>().ok())
        else {
            error!(log, "expected tfportqsfp$M_$N, got {}", ifname);
            continue;
        };

        let switch_port =
            match PortId::from_str(&format!("qsfp{}", egress_port_num)) {
                Ok(swp) => swp,
                Err(e) => {
                    error!(log, "bad port name: {e}");
                    continue;
                }
            };

        // TODO breakout considerations
        let link = dpd_client::types::LinkId(0);

        result.push(dpd_client::types::Route {
            tag: MG_LOWER_DPD_TAG.into(),
            cidr: dpd_client::Cidr::V4(dpd_client::Ipv4Cidr {
                prefix: r.prefix.value,
                prefix_len: r.prefix.length,
            }),
            switch_port,
            link,
            nexthop: Some(r.nexthop.into()),
            vid: None,
        });
    }

    result
}

fn handle_change(
    db: &Db,
    change: ChangeSet,
    log: &Logger,
    dpd: &DpdClient,
    generation: u64,
    rt: Arc<tokio::runtime::Handle>,
) -> u64 {
    if change.generation > generation + 1 {
        return initialize(db, log, dpd, rt.clone());
    }
    //TODO avoid this translation
    let to_add = change.import.added.clone().into_iter().collect();
    let to_add: HashSet<RouteHash> =
        db_route_to_dendrite_route(to_add, log, dpd)
            .iter()
            .map(|x| RouteHash(x.clone()))
            .collect();

    //TODO avoid this translation
    let to_del = change.import.removed.clone().into_iter().collect();
    let to_del: HashSet<RouteHash> =
        db_route_to_dendrite_route(to_del, log, dpd)
            .iter()
            .map(|x| RouteHash(x.clone()))
            .collect();

    update_dendrite(to_add.iter(), to_del.iter(), dpd, rt.clone(), log);

    change.generation
}

fn new_dpd_client(log: &Logger) -> DpdClient {
    let client_state = dpd_client::ClientState {
        tag: MG_LOWER_DPD_TAG.into(),
        log: log.clone(),
    };
    DpdClient::new(
        &format!("http://localhost:{}", dpd_client::default_port()),
        client_state,
    )
}
