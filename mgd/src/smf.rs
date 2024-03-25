// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use anyhow::anyhow;
use slog::{info, warn, Logger};
use smf::PropertyGroup;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use uuid::Uuid;

pub(crate) async fn smf_refresh(
    ctx: Arc<HandlerContext>,
    log: Logger,
) -> anyhow::Result<()> {
    let scf = smf::Scf::new()
        .map_err(|e| anyhow::anyhow!("create scf handle: {e}"))?;

    let instance = scf
        .get_self_instance()
        .map_err(|e| anyhow::anyhow!("create smf instance: {e}"))?;

    let snapshot = instance.get_running_snapshot().map_err(|e| {
        anyhow::anyhow!("get smf instnace running snapshot: {e}")
    })?;

    let prop_group = snapshot
        .get_pg("config")
        .map_err(|e| anyhow::anyhow!("get smf config properties group: {e}"))?;

    let prop_group = match prop_group {
        Some(pg) => pg,
        None => {
            warn!(log, "smf config properties group is empty");
            return Ok(());
        }
    };

    refresh_stats_server(&ctx, prop_group, &log)?;

    Ok(())
}

struct StatsServerProps {
    admin_addr: IpAddr,
    dns_servers: Vec<SocketAddr>,
    rack_uuid: Uuid,
    sled_uuid: Uuid,
}

fn get_stats_server_props(
    pg: PropertyGroup<'_>,
) -> anyhow::Result<StatsServerProps> {
    let admin_addr = get_string_prop("admin_addr", &pg)?;
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

fn refresh_stats_server(
    ctx: &Arc<HandlerContext>,
    pg: PropertyGroup<'_>,
    log: &Logger,
) -> anyhow::Result<()> {
    let hostname = hostname::get()
        .expect("failed to get hostname")
        .to_string_lossy()
        .to_string();

    let props = match get_stats_server_props(pg) {
        Ok(props) => props,
        Err(e) => {
            info!(log, "stats server not running on refresh: {e}");
            return Ok(());
        }
    };

    let mut is_running = ctx.stats_server_running.lock().unwrap();
    if !*is_running {
        info!(log, "starting stats server on smf refresh");
        crate::oxstats::start_server(
            props.admin_addr,
            ctx.clone(),
            props.dns_servers,
            hostname,
            props.rack_uuid,
            props.sled_uuid,
            log.clone(),
        )
        .unwrap();
        *is_running = true;
    } else {
        info!(log, "stats server already running on smf refresh");
    }

    Ok(())
}

fn get_string_prop(
    name: &str,
    pg: &PropertyGroup<'_>,
) -> anyhow::Result<String> {
    let prop = match pg
        .get_property(name)
        .map_err(|e| anyhow!("smf get-prop {name}: {e}"))?
    {
        Some(p) => p,
        None => anyhow::bail!("smf property {name} does not exist"),
    };

    let value = match prop
        .value()
        .map_err(|e| anyhow!("smf prop value {name}: {e}"))?
    {
        Some(v) => v,
        None => anyhow::bail!("smf property {name} has no value"),
    };

    value
        .as_string()
        .map_err(|e| anyhow!("smf prop value {name} as string: {e}"))
}

fn get_string_list_prop(
    name: &str,
    pg: &PropertyGroup<'_>,
) -> anyhow::Result<Vec<String>> {
    let prop = match pg
        .get_property(name)
        .map_err(|e| anyhow!("smf get-prop {name}: {e}"))?
    {
        Some(p) => p,
        None => anyhow::bail!("smf property {name} does not exist"),
    };

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
