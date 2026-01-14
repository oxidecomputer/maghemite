// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::bfd_admin::BfdContext;
use crate::bgp_admin::BgpContext;
use crate::log::dlog;
use bgp::connection_tcp::{BgpConnectionTcp, BgpListenerTcp};
use clap::{Parser, Subcommand};
use mg_common::cli::oxide_cli_style;
use mg_common::lock;
use mg_common::log::init_logger;
use mg_common::stats::MgLowerStats;
use rand::Fill;
use rdb::{BfdPeerConfig, BgpNeighborInfo, BgpRouterInfo};
use signal::handle_signals;
use slog::Logger;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::Builder;
use uuid::Uuid;

pub const COMPONENT_MGD: &str = "mgd";
pub const MOD_ADMIN: &str = "admin";
const UNIT_DAEMON: &str = "daemon";

mod admin;
mod bfd_admin;
mod bgp_admin;
mod error;
mod log;
mod mrib_admin;
mod oxstats;
mod rib_admin;
mod signal;
mod smf;
mod static_admin;
mod validation;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, styles = oxide_cli_style())]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the mgd routing daemon.
    Run(RunArgs),
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Address to listen on for the admin API.
    #[arg(long, default_value_t = Ipv6Addr::UNSPECIFIED.into())]
    admin_addr: IpAddr,

    /// Port to listen on for the admin API.
    #[arg(long, default_value_t = 4676)]
    admin_port: u16,

    /// Do not run a BGP connection dispatcher.
    #[arg(long, default_value_t = false)]
    no_bgp_dispatcher: bool,

    /// Where to store the local database
    #[arg(long, default_value = "/var/run")]
    data_dir: String,

    /// Register as an oximemeter producer.
    #[arg(long)]
    with_stats: bool,

    /// DNS servers used to find nexus.
    #[arg(long)]
    dns_servers: Vec<String>,

    /// Port to listen on for the oximeter API.
    #[arg(long, default_value_t = 4677)]
    oximeter_port: u16,

    /// Id of the rack this router is running on.
    #[arg(long)]
    rack_uuid: Option<Uuid>,

    /// Id of the sled this router is running on.
    #[arg(long)]
    sled_uuid: Option<Uuid>,

    /// SocketAddr the MGS service is listening on.
    #[arg(long, default_value = "[::1]:12225")]
    mgs_addr: SocketAddr,
}

fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Run(run_args) => oxide_tokio_rt::run(run(run_args)),
    }
}

async fn run(args: RunArgs) {
    let log = init_logger();

    let (sig_tx, sig_rx) = tokio::sync::mpsc::channel(1);
    handle_signals(sig_rx, log.clone())
        .await
        .expect("set up refresh signal handler");

    let bgp = init_bgp(&args, &log);
    let db = rdb::Db::new(&format!("{}/rdb", args.data_dir), log.clone())
        .expect("open datastore file");

    let tep_ula = get_tunnel_endpoint_ula(&db);
    let bfd = BfdContext::new(log.clone());

    let context = Arc::new(HandlerContext {
        tep: tep_ula,
        log: log.clone(),
        bgp,
        bfd,
        mg_lower_stats: Arc::new(MgLowerStats::default()),
        db: db.clone(),
        stats_server_running: Mutex::new(false),
        oximeter_port: args.oximeter_port,
    });

    detect_switch_slot(
        context.clone(),
        args.mgs_addr,
        tokio::runtime::Handle::current(),
    );

    if let Err(e) = sig_tx.send(context.clone()).await {
        dlog!(log, error, "error sending handler context to signal handler: {e}";
            "params" => format!("tep {tep_ula}, dir {}, oximeter_port {}",
                args.data_dir.clone(), args.oximeter_port
            ),
            "error" => format!("{e}")
        );
    }

    #[cfg(feature = "mg-lower")]
    {
        let rt = Arc::new(tokio::runtime::Handle::current());
        let ctx = context.clone();
        let log = log.clone();
        let db = ctx.db.clone();
        let stats = context.mg_lower_stats.clone();
        Builder::new()
            .name("mg-lower".to_string())
            .spawn(move || {
                mg_lower::run(ctx.tep, db, log, stats, rt);
            })
            .expect("failed to start mg-lower");
    }

    start_bgp_routers(
        context.clone(),
        db.get_bgp_routers()
            .expect("get BGP routers from datastore"),
        db.get_bgp_neighbors()
            .expect("get BGP neighbors from data store"),
    );

    start_bfd_sessions(
        context.clone(),
        db.get_bfd_neighbors()
            .expect("get BFD neighbors from data store"),
    );

    initialize_static_routes(&db, &context.log);

    let hostname = hostname::get()
        .expect("failed to get hostname")
        .to_string_lossy()
        .to_string();

    if args.with_stats
        && let (Some(rack_uuid), Some(sled_uuid)) =
            (args.rack_uuid, args.sled_uuid)
    {
        let mut is_running = lock!(context.stats_server_running);
        if !*is_running {
            match oxstats::start_server(
                context.clone(),
                &hostname,
                rack_uuid,
                sled_uuid,
                log.clone(),
            ) {
                Ok(_) => *is_running = true,
                Err(e) => {
                    dlog!(log, error, "failed to start stats server: {e}";
                        "params" => format!("hostname {hostname}, rack {rack_uuid}, sled {sled_uuid}"),
                        "error" => format!("{e}")
                    )
                }
            }
        }
    }

    let j = admin::start_server(
        log.clone(),
        args.admin_addr,
        args.admin_port,
        context.clone(),
    )
    .expect("start API server");
    j.await.expect("API server quit unexpectedly");
}

fn detect_switch_slot(
    ctx: Arc<HandlerContext>,
    mgs_socket_addr: SocketAddr,
    rt: tokio::runtime::Handle,
) {
    let url = format!("http://{mgs_socket_addr}");
    let client_log = ctx.log.new(slog::o!("unit" => "gateway-client"));
    let task = async move || {
        let client = gateway_client::Client::new(&url, client_log);
        let ctx = ctx.clone();

        loop {
            // check in with gateway
            let gateway_client::types::SpIdentifier { slot, .. } = match client
                .sp_local_switch_id()
                .await
            {
                Ok(v) => *v,
                Err(e) => {
                    slog::error!(ctx.log, "failed to resolve switch slot"; "error" => %e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(10))
                        .await;
                    continue;
                }
            };

            slog::info!(ctx.log, "we are in switch slot {slot}");

            // update db
            let mut db = ctx.db.clone();
            db.set_slot(Some(slot));
            break;
        }
    };

    rt.spawn(task());
}

fn init_bgp(args: &RunArgs, log: &Logger) -> BgpContext {
    let addr_to_session = Arc::new(Mutex::new(BTreeMap::new()));
    if !args.no_bgp_dispatcher {
        let bgp_dispatcher =
            bgp::dispatcher::Dispatcher::<BgpConnectionTcp>::new(
                addr_to_session.clone(),
                "[::]:179".into(),
                log.clone(),
            );

        let listener_str =
            format!("bgp-dispatcher-{}", bgp_dispatcher.listen_addr());

        Builder::new()
            .name(listener_str.clone())
            .spawn(move || bgp_dispatcher.run::<BgpListenerTcp>())
            .expect("failed to start {listener_str}");
    }
    BgpContext::new(addr_to_session)
}

fn start_bgp_routers(
    context: Arc<HandlerContext>,
    routers: BTreeMap<u32, BgpRouterInfo>,
    neighbors: Vec<BgpNeighborInfo>,
) {
    dlog!(context.log, info, "starting bgp routers: {routers:#?}");
    let mut guard = context.bgp.router.lock().expect("lock bgp routers");
    for (asn, info) in routers {
        bgp_admin::helpers::add_router(
            context.clone(),
            bgp::params::Router {
                asn,
                id: info.id,
                listen: info.listen.clone(),
                graceful_shutdown: info.graceful_shutdown,
            },
            &mut guard,
        )
        .unwrap_or_else(|_| panic!("add BGP router {asn} {info:#?}"));
    }
    drop(guard);

    for nbr in neighbors {
        bgp_admin::helpers::add_neighbor(
            context.clone(),
            bgp::params::Neighbor {
                asn: nbr.asn,
                remote_asn: nbr.remote_asn,
                min_ttl: nbr.min_ttl,
                name: nbr.name.clone(),
                host: nbr.host,
                hold_time: nbr.hold_time,
                idle_hold_time: nbr.idle_hold_time,
                delay_open: nbr.delay_open,
                connect_retry: nbr.connect_retry,
                keepalive: nbr.keepalive,
                resolution: nbr.resolution,
                group: nbr.group.clone(),
                passive: nbr.passive,
                md5_auth_key: nbr.md5_auth_key.clone(),
                multi_exit_discriminator: nbr.multi_exit_discriminator,
                communities: nbr.communities.clone(),
                local_pref: nbr.local_pref,
                enforce_first_as: nbr.enforce_first_as,
                allow_import: nbr.allow_import.clone(),
                allow_export: nbr.allow_export.clone(),
                vlan_id: nbr.vlan_id,
            },
            true,
        )
        .unwrap_or_else(|_| panic!("add BGP neighbor {nbr:#?}"));
    }
}

fn start_bfd_sessions(
    context: Arc<HandlerContext>,
    configs: Vec<BfdPeerConfig>,
) {
    dlog!(context.log, info, "starting bfd sessions: {configs:#?}");
    for config in configs {
        bfd_admin::add_peer(context.clone(), config)
            .unwrap_or_else(|e| panic!("failed to add bfd peer {e}"));
    }
}

// Read static routes from disk, normalize prefixes by unsetting host bits,
// deduplicate, and re-add them to the db (updating both the on-disk db and
// the rib). This handles migration from old versions where host bits weren't
// automatically zeroed, and consolidates routes that differ only in host bits
// into ECMP routes.
fn initialize_static_routes(db: &rdb::Db, log: &Logger) {
    let routes = db
        .get_static(None)
        .expect("failed to get static routes from db");

    let original_count = routes.len();

    // Normalize all prefixes by unsetting host bits and deduplicate.
    // BTreeSet automatically deduplicates routes that become identical after
    // normalization (same prefix + nexthop + vlan_id + rib_priority).
    let normalized: BTreeSet<rdb::StaticRouteKey> = routes
        .iter()
        .map(|srk| {
            let mut normalized = *srk;
            normalized.prefix.unset_host_bits();
            normalized
        })
        .collect();

    let normalized_count = normalized.len();

    // Remove all old routes (both normalized and unnormalized) from the
    // persistent DB to ensure a clean state.
    db.remove_static_routes(&routes).unwrap_or_else(|e| {
        panic!("failed to remove old static routes during normalization: {e}")
    });

    // Add back the normalized, deduplicated routes.
    let normalized_vec: Vec<_> = normalized.into_iter().collect();
    db.add_static_routes(&normalized_vec).unwrap_or_else(|e| {
        panic!(
            "failed to add normalized static routes {normalized_vec:#?}: {e}"
        )
    });

    // Log information about the normalization process if any changes occurred.
    if original_count != normalized_count {
        slog::info!(
            log,
            "normalized static routes on startup";
            "original_count" => original_count,
            "normalized_count" => normalized_count,
            "deduplicated" => original_count - normalized_count,
        );
    }
}

fn get_tunnel_endpoint_ula(db: &rdb::Db) -> Ipv6Addr {
    if let Some(addr) = db.get_tep_addr().unwrap() {
        return addr;
    }

    // creat the randomized ULA fdxx:xxxx:xxxx:xxxx::1 as a tunnel endpoint
    let mut rng = rand::thread_rng();
    let mut r = [0u8; 7];
    r.try_fill(&mut rng).unwrap();
    let tep_ula = Ipv6Addr::from([
        0xfd, r[0], r[1], r[2], r[3], r[4], r[5], r[6], 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    db.set_tep_addr(tep_ula).unwrap();

    tep_ula
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdb::{Prefix, Prefix4, Prefix6, StaticRouteKey};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use tempfile::TempDir;

    fn setup_test_db() -> (rdb::Db, TempDir, Logger) {
        let temp_dir = TempDir::new().unwrap();
        let log = mg_common::log::init_logger();
        let db = rdb::Db::new(temp_dir.path().to_str().unwrap(), log.clone())
            .unwrap();
        (db, temp_dir, log)
    }

    #[test]
    fn test_initialize_static_routes_deduplicates_same_nexthop() {
        let (db, _temp, log) = setup_test_db();

        // Add two routes with different host bits but same nexthop
        // They should normalize to the same route and deduplicate
        let routes = vec![
            StaticRouteKey {
                prefix: Prefix::V4(Prefix4 {
                    value: Ipv4Addr::from_str("10.0.0.1").unwrap(),
                    length: 24,
                }),
                nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
            StaticRouteKey {
                prefix: Prefix::V4(Prefix4 {
                    value: Ipv4Addr::from_str("10.0.0.5").unwrap(),
                    length: 24,
                }),
                nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
        ];

        db.add_static_routes(&routes).unwrap();

        // Verify we have 2 routes before normalization
        let before = db.get_static(None).unwrap();
        assert_eq!(before.len(), 2);

        // Run initialization
        initialize_static_routes(&db, &log);

        // Verify we have 1 route after normalization (deduplicated)
        let after = db.get_static(None).unwrap();
        assert_eq!(after.len(), 1);

        // Verify the route has the normalized prefix
        let route = &after[0];
        assert_eq!(
            route.prefix,
            Prefix::V4(Prefix4::new(
                Ipv4Addr::from_str("10.0.0.0").unwrap(),
                24
            ))
        );
        assert_eq!(
            route.nexthop,
            IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap())
        );
    }

    #[test]
    fn test_initialize_static_routes_creates_ecmp() {
        let (db, _temp, log) = setup_test_db();

        // Add two routes with different host bits AND different nexthops
        // They should normalize to the same prefix but keep both routes (ECMP)
        let routes = vec![
            StaticRouteKey {
                prefix: Prefix::V4(Prefix4 {
                    value: Ipv4Addr::from_str("10.0.0.1").unwrap(),
                    length: 24,
                }),
                nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
            StaticRouteKey {
                prefix: Prefix::V4(Prefix4 {
                    value: Ipv4Addr::from_str("10.0.0.5").unwrap(),
                    length: 24,
                }),
                nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.2").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
        ];

        db.add_static_routes(&routes).unwrap();

        // Verify we have 2 routes before normalization
        let before = db.get_static(None).unwrap();
        assert_eq!(before.len(), 2);

        // Run initialization
        initialize_static_routes(&db, &log);

        // Verify we still have 2 routes after normalization (ECMP)
        let after = db.get_static(None).unwrap();
        assert_eq!(after.len(), 2);

        // Verify both routes have the normalized prefix but different nexthops
        for route in &after {
            assert_eq!(
                route.prefix,
                Prefix::V4(Prefix4::new(
                    Ipv4Addr::from_str("10.0.0.0").unwrap(),
                    24
                ))
            );
        }
        assert_ne!(after[0].nexthop, after[1].nexthop);
    }

    #[test]
    fn test_initialize_static_routes_preserves_normalized() {
        let (db, _temp, log) = setup_test_db();

        // Add a route that's already normalized
        let routes = vec![StaticRouteKey {
            prefix: Prefix::V4(Prefix4::new(
                Ipv4Addr::from_str("10.0.0.0").unwrap(),
                24,
            )),
            nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
            vlan_id: None,
            rib_priority: 0,
        }];

        db.add_static_routes(&routes).unwrap();

        // Run initialization
        initialize_static_routes(&db, &log);

        // Verify the route is unchanged
        let after = db.get_static(None).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0], routes[0]);
    }

    #[test]
    fn test_initialize_static_routes_empty_db() {
        let (db, _temp, log) = setup_test_db();

        // Run initialization on empty DB - should not panic
        initialize_static_routes(&db, &log);

        // Verify DB is still empty
        let after = db.get_static(None).unwrap();
        assert_eq!(after.len(), 0);
    }

    #[test]
    fn test_initialize_static_routes_ipv6() {
        let (db, _temp, log) = setup_test_db();

        // Test IPv6 normalization
        let routes = vec![
            StaticRouteKey {
                prefix: Prefix::V6(Prefix6 {
                    value: Ipv6Addr::from_str("2001:db8::1").unwrap(),
                    length: 64,
                }),
                nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
            StaticRouteKey {
                prefix: Prefix::V6(Prefix6 {
                    value: Ipv6Addr::from_str("2001:db8::5").unwrap(),
                    length: 64,
                }),
                nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::2").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
        ];

        db.add_static_routes(&routes).unwrap();

        // Run initialization
        initialize_static_routes(&db, &log);

        // Verify we have 2 routes (ECMP) with normalized prefix
        let after = db.get_static(None).unwrap();
        assert_eq!(after.len(), 2);
        for route in &after {
            assert_eq!(
                route.prefix,
                Prefix::V6(Prefix6::new(
                    Ipv6Addr::from_str("2001:db8::").unwrap(),
                    64
                ))
            );
        }
    }

    #[test]
    fn test_initialize_static_routes_mixed_families() {
        let (db, _temp, log) = setup_test_db();

        // Test mixed IPv4 and IPv6 routes
        let routes = vec![
            StaticRouteKey {
                prefix: Prefix::V4(Prefix4 {
                    value: Ipv4Addr::from_str("10.0.0.1").unwrap(),
                    length: 24,
                }),
                nexthop: IpAddr::V4(Ipv4Addr::from_str("192.168.1.1").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
            StaticRouteKey {
                prefix: Prefix::V6(Prefix6 {
                    value: Ipv6Addr::from_str("2001:db8::1").unwrap(),
                    length: 64,
                }),
                nexthop: IpAddr::V6(Ipv6Addr::from_str("fe80::1").unwrap()),
                vlan_id: None,
                rib_priority: 0,
            },
        ];

        db.add_static_routes(&routes).unwrap();

        // Run initialization
        initialize_static_routes(&db, &log);

        // Verify both routes are normalized
        let after = db.get_static(None).unwrap();
        assert_eq!(after.len(), 2);
        assert!(after[0].prefix.host_bits_are_unset());
        assert!(after[1].prefix.host_bits_are_unset());
    }
}
