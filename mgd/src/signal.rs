// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::log::sig_log;
use crate::smf::smf_refresh;
use slog::Logger;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::Receiver;

const UNIT_SIG: &str = "signal";

pub(crate) async fn handle_signals(
    mut ch: Receiver<Arc<HandlerContext>>,
    log: Logger,
) -> anyhow::Result<()> {
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        sig_log!(log, info, "signal handler waiting for context");
        let ctx = loop {
            match ch.recv().await {
                Some(ctx) => break ctx,
                None => continue,
            }
        };
        sig_log!(log, info, "signal handler got context");

        loop {
            sigusr1.recv().await;
            if let Err(e) = smf_refresh(ctx.clone(), log.clone()).await {
                sig_log!(log, error, "smf update on sigusr1 failed: {e}";
                    "error" => format!("{e}")
                );
            }
        }
    });
    Ok(())
}
