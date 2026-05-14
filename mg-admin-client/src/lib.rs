// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

progenitor::generate_api!(
    spec = "../openapi/mg-admin/mg-admin-latest.json",
    inner_type = slog::Logger,
    pre_hook = (|log: &slog::Logger, request: &reqwest::Request| {
        slog::trace!(log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    post_hook = (|log: &slog::Logger, result: &Result<_, _>| {
        slog::trace!(log, "client response"; "result" => ?result);
    }),
    derives = [schemars::JsonSchema],
    replace = {
        // Routing-database shapes.
        Prefix4 = mg_api_types_versions::latest::rdb::prefix::Prefix4,
        Prefix6 = mg_api_types_versions::latest::rdb::prefix::Prefix6,
        Prefix = mg_api_types_versions::latest::rdb::prefix::Prefix,
        AddressFamily = mg_api_types_versions::latest::rdb::rib::AddressFamily,
        ProtocolFilter = mg_api_types_versions::latest::rdb::rib::ProtocolFilter,

        // BGP policy and peer-identity shapes.
        ImportExportPolicy4 = mg_api_types_versions::latest::bgp::policy::ImportExportPolicy4,
        ImportExportPolicy6 = mg_api_types_versions::latest::bgp::policy::ImportExportPolicy6,
        PeerId = mg_api_types_versions::latest::bgp::peer::PeerId,

        // BGP admin shapes.
        CheckerSource = mg_api_types_versions::latest::bgp::config::CheckerSource,
        ExportedSelector = mg_api_types_versions::latest::bgp::session::ExportedSelector,
        FsmEventBuffer = mg_api_types_versions::latest::bgp::history::FsmEventBuffer,
        Ipv4UnicastConfig = mg_api_types_versions::latest::bgp::config::Ipv4UnicastConfig,
        Ipv6UnicastConfig = mg_api_types_versions::latest::bgp::config::Ipv6UnicastConfig,
        JitterRange = mg_api_types_versions::latest::bgp::config::JitterRange,
        MessageDirection = mg_api_types_versions::latest::bgp::history::MessageDirection,
        NeighborResetOp = mg_api_types_versions::latest::bgp::config::NeighborResetOp,
        NeighborResetRequest = mg_api_types_versions::latest::bgp::config::NeighborResetRequest,
        Origin4 = mg_api_types_versions::latest::bgp::config::Origin4,
        Origin6 = mg_api_types_versions::latest::bgp::history::Origin6,
        PeerInfo = mg_api_types_versions::latest::bgp::config::PeerInfo,
        Router = mg_api_types_versions::latest::bgp::config::Router,
        ShaperSource = mg_api_types_versions::latest::bgp::config::ShaperSource,
        UnnumberedNeighborResetRequest = mg_api_types_versions::latest::bgp::config::UnnumberedNeighborResetRequest,

        FsmStateKind = mg_api_types_versions::latest::bgp::session::FsmStateKind,

        // BGP wire-message shapes.
        Afi = mg_api_types_versions::latest::bgp::messages::Afi,

        // RIB shapes.
        BestpathFanoutRequest = mg_api_types_versions::latest::rib::BestpathFanoutRequest,

        // Static-route shapes.
        AddStaticRoute4Request = mg_api_types_versions::latest::static_routes::AddStaticRoute4Request,
        AddStaticRoute6Request = mg_api_types_versions::latest::static_routes::AddStaticRoute6Request,
        DeleteStaticRoute4Request = mg_api_types_versions::latest::static_routes::DeleteStaticRoute4Request,
        DeleteStaticRoute6Request = mg_api_types_versions::latest::static_routes::DeleteStaticRoute6Request,
        StaticRoute4 = mg_api_types_versions::latest::static_routes::StaticRoute4,
        StaticRoute4List = mg_api_types_versions::latest::static_routes::StaticRoute4List,
        StaticRoute6 = mg_api_types_versions::latest::static_routes::StaticRoute6,
        StaticRoute6List = mg_api_types_versions::latest::static_routes::StaticRoute6List,

        Duration = std::time::Duration,
    }
);

use colored::*;
use mg_api_types_versions::latest::rdb::prefix::Prefix;
use mg_api_types_versions::latest::rdb::rib::{AddressFamily, ProtocolFilter};
use std::collections::BTreeMap;
use std::io::{Write, stdout};
use tabwriter::TabWriter;
use types::{Path, Rib};

pub fn print_rib(
    rib: Rib,
    address_family: Option<AddressFamily>,
    protocol_filter: Option<ProtocolFilter>,
) {
    type CliRib = BTreeMap<Prefix, Vec<Path>>;

    // Always split into 4 collections
    let mut v4_static = CliRib::new();
    let mut v4_bgp = CliRib::new();
    let mut v6_static = CliRib::new();
    let mut v6_bgp = CliRib::new();

    // Parse and categorize all routes
    for (prefix, paths) in rib.0.into_iter() {
        let pfx: Prefix = match prefix.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("failed to parse prefix [{prefix}]: {e}");
                continue;
            }
        };

        let (bgp_paths, static_paths): (Vec<Path>, Vec<Path>) =
            paths.into_iter().partition(|p| p.bgp.is_some());

        match pfx {
            Prefix::V4(_) => {
                if !static_paths.is_empty() {
                    v4_static.insert(pfx, static_paths);
                }
                if !bgp_paths.is_empty() {
                    v4_bgp.insert(pfx, bgp_paths);
                }
            }
            Prefix::V6(_) => {
                if !static_paths.is_empty() {
                    v6_static.insert(pfx, static_paths);
                }
                if !bgp_paths.is_empty() {
                    v6_bgp.insert(pfx, bgp_paths);
                }
            }
        }
    }

    let show_ipv4 = matches!(address_family, None | Some(AddressFamily::Ipv4));
    let show_ipv6 = matches!(address_family, None | Some(AddressFamily::Ipv6));
    let show_static =
        matches!(protocol_filter, None | Some(ProtocolFilter::Static));
    let show_bgp = matches!(protocol_filter, None | Some(ProtocolFilter::Bgp));

    if show_ipv4 && show_static && !v4_static.is_empty() {
        print_static_routes(&v4_static, "Static Routes (IPv4)");
    }

    if show_ipv4 && show_bgp && !v4_bgp.is_empty() {
        print_bgp_routes(&v4_bgp, "BGP Routes (IPv4)");
    }

    if show_ipv6 && show_static && !v6_static.is_empty() {
        print_static_routes(&v6_static, "Static Routes (IPv6)");
    }

    if show_ipv6 && show_bgp && !v6_bgp.is_empty() {
        print_bgp_routes(&v6_bgp, "BGP Routes (IPv6)");
    }
}

fn print_static_routes(routes: &BTreeMap<Prefix, Vec<Path>>, title: &str) {
    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}",
        "Prefix".dimmed(),
        "Nexthop".dimmed(),
        "RIB Priority".dimmed(),
    )
    .unwrap();

    for (prefix, paths) in routes.iter() {
        write!(&mut tw, "{prefix}").unwrap();
        for path in paths.iter() {
            let nexthop_display = match &path.nexthop_interface {
                Some(iface) => format!("{}({})", iface, path.nexthop),
                None => path.nexthop.to_string(),
            };
            writeln!(
                &mut tw,
                "\t{}\t{:?}",
                nexthop_display,
                path.rib_priority,
            )
            .unwrap();
        }
    }

    println!("{}", title.dimmed());
    println!("{}", "=".repeat(title.len()).dimmed());
    tw.flush().unwrap();
}

fn print_bgp_routes(routes: &BTreeMap<Prefix, Vec<Path>>, title: &str) {
    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "Prefix".dimmed(),
        "Nexthop".dimmed(),
        "RIB Priority".dimmed(),
        "Local Pref".dimmed(),
        "Origin AS".dimmed(),
        "Peer".dimmed(),
        "MED".dimmed(),
        "AS Path".dimmed(),
        "Stale".dimmed(),
    )
    .unwrap();

    for (prefix, paths) in routes.iter() {
        write!(&mut tw, "{prefix}").unwrap();
        for path in paths.iter() {
            let bgp = path.bgp.as_ref().unwrap();
            let nexthop_display = match &path.nexthop_interface {
                Some(iface) => format!("{}({})", iface, path.nexthop),
                None => path.nexthop.to_string(),
            };
            let peer_str = match &bgp.peer {
                mg_api_types_versions::latest::bgp::peer::PeerId::Ip(ip) => {
                    ip.to_string()
                }
                mg_api_types_versions::latest::bgp::peer::PeerId::Interface(
                    iface,
                ) => iface.clone(),
            };
            writeln!(
                &mut tw,
                "\t{}\t{}\t{:?}\t{}\t{}\t{:?}\t{:?}\t{:?}",
                nexthop_display,
                path.rib_priority,
                bgp.local_pref,
                bgp.origin_as,
                peer_str,
                bgp.med,
                bgp.as_path,
                bgp.stale,
            )
            .unwrap();
        }
    }

    println!("{}", title.dimmed());
    println!("{}", "=".repeat(title.len()).dimmed());
    tw.flush().unwrap();
}
