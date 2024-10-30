// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::IpAddr;

use anyhow::anyhow;
use omicron_common::api::internal::shared::SledIdentifiers;
use smf::PropertyGroup;

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
    pub sled_idents: SledIdentifiers,
}

pub fn get_stats_server_props(
    pg: PropertyGroup<'_>,
) -> anyhow::Result<StatsServerProps> {
    let admin_addr = get_string_prop("admin_host", &pg)?;
    let rack_id = get_string_prop("rack_id", &pg)?;
    let sled_id = get_string_prop("sled_id", &pg)?;
    let sled_model = get_string_prop("sled_model", &pg)?;
    let sled_revision = get_string_prop("sled_revision", &pg)?;
    let sled_serial = get_string_prop("sled_serial", &pg)?;

    Ok(StatsServerProps {
        admin_addr: admin_addr
            .parse()
            .map_err(|e| anyhow!("parse admin addr: {e}"))?,
        sled_idents: SledIdentifiers {
            rack_id: rack_id
                .parse()
                .map_err(|e| anyhow!("parse rack id {rack_id}: {e}"))?,
            sled_id: sled_id
                .parse()
                .map_err(|e| anyhow!("parse sled id {sled_id}: {e}"))?,
            model: sled_model,
            revision: sled_revision.parse().map_err(|e| {
                anyhow!("parse sled revision {sled_revision}: {e}")
            })?,
            serial: sled_serial,
        },
    })
}
