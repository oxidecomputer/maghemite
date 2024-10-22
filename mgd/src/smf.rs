// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use mg_common::lock;
use mg_common::smf::get_stats_server_props;
use slog::{error, info, warn, Logger};
use smf::PropertyGroup;
use std::sync::Arc;

pub(crate) async fn smf_refresh(
    ctx: Arc<HandlerContext>,
    log: Logger,
) -> anyhow::Result<()> {
    info!(log, "handling smf refresh");
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

    let mut is_running = lock!(ctx.stats_server_running);
    if !*is_running {
        info!(log, "starting stats server on smf refresh");
        match crate::oxstats::start_server(
            ctx.clone(),
            hostname,
            props.rack_uuid,
            props.sled_uuid,
            log.clone(),
        ) {
            Ok(_) => {
                *is_running = true;
            }
            Err(e) => {
                error!(log, "failed to start stats server on refresh: {e}");
            }
        }
    } else {
        info!(log, "stats server already running on smf refresh");
    }

    Ok(())
}
