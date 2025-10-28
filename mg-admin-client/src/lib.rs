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
        Prefix4 = rdb::Prefix4,
        Prefix6 = rdb::Prefix6,
        Prefix = rdb::Prefix,
        AddressFamily = rdb::types::AddressFamily,
        ProtocolFilter = rdb::types::ProtocolFilter,
    }
);

use colored::*;
use rdb::Prefix;
use rdb::types::{AddressFamily, ProtocolFilter};
use std::collections::BTreeMap;
use std::io::{Write, stdout};
use std::net::Ipv4Addr;
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
            writeln!(&mut tw, "\t{}\t{:?}", path.nexthop, path.rib_priority,)
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
        "Peer ID".dimmed(),
        "MED".dimmed(),
        "AS Path".dimmed(),
        "Stale".dimmed(),
    )
    .unwrap();

    for (prefix, paths) in routes.iter() {
        write!(&mut tw, "{prefix}").unwrap();
        for path in paths.iter() {
            let bgp = path.bgp.as_ref().unwrap();
            writeln!(
                &mut tw,
                "\t{}\t{}\t{:?}\t{}\t{}\t{:?}\t{:?}\t{:?}",
                path.nexthop,
                path.rib_priority,
                bgp.local_pref,
                bgp.origin_as,
                Ipv4Addr::from(bgp.id),
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
