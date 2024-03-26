// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::smf::smf_refresh;
use ddm::admin::HandlerContext;
use slog::{error, info, Logger};
use std::sync::{Arc, Mutex};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::Receiver;

pub(crate) async fn handle_signals(
    mut ch: Receiver<Arc<Mutex<HandlerContext>>>,
    log: Logger,
) {
    tokio::spawn(async move {
        let mut sigusr1 = signal(SignalKind::user_defined1()).unwrap();
        let mut future_signal = sigusr1.recv();

        info!(log, "signal handler waiting for context");
        let ctx = loop {
            match ch.recv().await {
                Some(ctx) => break ctx,
                None => continue,
            }
        };
        info!(log, "signal handler waiting got context");

        loop {
            future_signal.await;
            if let Err(e) = smf_refresh(ctx.clone(), log.clone()).await {
                error!(log, "smf update on sigusr1 failed: {e}");
            }
            future_signal = sigusr1.recv();
        }
    });
}
