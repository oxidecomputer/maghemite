// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::log::smf_log;
use mg_common::lock;
use mg_common::smf::get_stats_server_props;
use slog::Logger;
use smf::PropertyGroup;
use std::sync::Arc;

const UNIT_SMF: &str = "smf";

pub(crate) async fn smf_refresh(
    ctx: Arc<HandlerContext>,
    log: Logger,
) -> anyhow::Result<()> {
    smf_log!(log, info, "handling smf refresh");
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
            smf_log!(log, warn, "smf config properties group is empty");
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
            smf_log!(log, info, "stats server not running on refresh: {e}");
            return Ok(());
        }
    };

    let mut is_running = lock!(ctx.stats_server_running);
    if !*is_running {
        smf_log!(log, info, "starting stats server on smf refresh");
        match crate::oxstats::start_server(
            ctx.clone(),
            &hostname,
            props.rack_uuid,
            props.sled_uuid,
            log.clone(),
        ) {
            Ok(_) => {
                smf_log!(log, info, "started stats server on smf refresh");
                *is_running = true;
            }
            Err(e) => {
                smf_log!(log, error, "failed to start stats server on refresh: {e}";
                    "error" => format!("{e}")
                );
            }
        }
    } else {
        smf_log!(log, info, "stats server already running on refresh");
    }

    Ok(())
}
