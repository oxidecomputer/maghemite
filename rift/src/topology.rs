// Copyright 2021 Oxide Computer Company

use std::sync::Arc;
use tokio::{
    spawn, //select,
    //time::sleep,
    //task::JoinHandle,
    sync::{Mutex, mpsc::{Sender, Receiver}},
};
use rift_protocol::{tie::TIEPacket};
use crate::{
    Platform,
};
use platform::TIEPacketTx;
use slog::{
    //info,
    //debug,
    error,
    trace,
    //warn,
};

pub(crate) async fn tie_entry<P: Platform + Send + Sync + 'static>(
    log: slog::Logger,
    platform: Arc::<Mutex::<P>>,
) {
    trace!(log, "TIE entry");

    let (tx, rx) = {
        let p = platform.lock().await;
        match p.get_topology_channel() {
            Err(e) => {
                error!(log, "get topology channel: {}", e);
                return;
            }
            Ok(cs) => cs
        }
    };

    tie_loop(
        log.clone(), 
        tx,
        rx,
    );

}

fn tie_loop(
    log: slog::Logger,
    _tx: Sender<TIEPacketTx>,
    mut _rx: Receiver<TIEPacket>,
) {

    spawn(async move {

        trace!(log, "TIE loop");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    });

}
