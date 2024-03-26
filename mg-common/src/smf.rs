// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{IpAddr, SocketAddr};

use anyhow::anyhow;
use smf::PropertyGroup;
use uuid::Uuid;

pub fn get_string_prop(
    name: &str,
    pg: &PropertyGroup<'_>,
) -> anyhow::Result<String> {
    let prop = pg
        .get_property(name)
        .map_err(|e| anyhow!("smf get-prop {name}: {e}"))?
        .ok_or_else(|| anyhow!("smf property {name} does not exist"))?;

    let value = prop
        .value()
        .map_err(|e| anyhow!("smf prop value {name}: {e}"))?
        .ok_or_else(|| anyhow!("smf property {name} has no value"))?;

    value
        .as_string()
        .map_err(|e| anyhow!("smf prop value {name} as string: {e}"))
}

pub fn get_string_list_prop(
    name: &str,
    pg: &PropertyGroup<'_>,
) -> anyhow::Result<Vec<String>> {
    let prop = pg
        .get_property(name)
        .map_err(|e| anyhow!("smf get-prop {name}: {e}"))?
        .ok_or_else(|| anyhow!("smf property {name} does not exist"))?;

    let values = prop
        .values()
        .map_err(|e| anyhow!("smf prop value {name}: {e}"))?;

    let mut result = Vec::new();

    for v in values {
        result.push(
            v.as_ref()
                .map_err(|e| {
                    anyhow!("smf prop value item {v:?} in {name}: {e}")
                })?
                .as_string()
                .map_err(|e| {
                    anyhow!(
                        "smf prop value item {v:?} in {name} as string: {e}"
                    )
                })?,
        );
    }

    Ok(result)
}

pub struct StatsServerProps {
    pub admin_addr: IpAddr,
    pub dns_servers: Vec<SocketAddr>,
    pub rack_uuid: Uuid,
    pub sled_uuid: Uuid,
}

pub fn get_stats_server_props(
    pg: PropertyGroup<'_>,
) -> anyhow::Result<StatsServerProps> {
    let admin_addr = get_string_prop("admin_host", &pg)?;
    let dns_servers_prop = get_string_list_prop("dns_servers", &pg)?;
    let rack_uuid = get_string_prop("rack_uuid", &pg)?;
    let sled_uuid = get_string_prop("sled_uuid", &pg)?;

    let mut dns_servers = Vec::new();
    for p in &dns_servers_prop {
        dns_servers.push(
            p.parse()
                .map_err(|e| anyhow!("parse dns server {p}: {e}"))?,
        );
    }

    Ok(StatsServerProps {
        admin_addr: admin_addr
            .parse()
            .map_err(|e| anyhow!("parse admin addr: {e}"))?,
        dns_servers,
        rack_uuid: rack_uuid
            .parse()
            .map_err(|e| anyhow!("parse rack uuid {rack_uuid}: {e}"))?,
        sled_uuid: sled_uuid
            .parse()
            .map_err(|e| anyhow!("parse rack uuid {rack_uuid}: {e}"))?,
    })
}
