// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Per-session applier that pushes BFD nexthop-shutdown state into the RIB.
//!
//! Writing to the RIB (`rdb`) is a blocking operation, so we have to move it
//! off of the async worker threads via `tokio::spawn_blocking()` whenever there
//! are changes to publish. This task subscribes to a [`watch`] channel; the
//! sending half is owned by the [`crate::Session`]'s driver task, which updates
//! it whenever the session state changes.
//!
//! Because watch channels only contain the latest value, a slow RIB write
//! can neither stall the driver nor pile up work: intermediate values are
//! skipped and only the current state at time of execution will be applied. If
//! we have a session that's flapping faster than the RIB syncs can execute,
//! we'll miss some flaps, but that seems okay: the final write will always be
//! consistent with the session state once the flapping ends.

use mg_api_types::bfd::BfdPeerState;
use std::net::IpAddr;
use tokio::sync::watch;

/// Dependency injection trait for nexthop-shutdown updates. Production uses
/// [`rdb::Db`]; tests can pass a different (fake) impl.
trait NexthopSink: Clone + Send + 'static {
    fn set_nexthop_shutdown(&self, nexthop: IpAddr, shutdown: bool);
}

impl NexthopSink for rdb::Db {
    fn set_nexthop_shutdown(&self, nexthop: IpAddr, shutdown: bool) {
        rdb::Db::set_nexthop_shutdown(self, nexthop, shutdown);
    }
}

pub(crate) struct RibTask {
    nexthop: IpAddr,
    state_rx: watch::Receiver<BfdPeerState>,
}

impl RibTask {
    pub(crate) fn new(
        nexthop: IpAddr,
        state_rx: watch::Receiver<BfdPeerState>,
    ) -> Self {
        Self { nexthop, state_rx }
    }

    pub(crate) async fn run(self, db: rdb::Db) {
        self.run_impl(db).await
    }

    async fn run_impl<S: NexthopSink>(mut self, sink: S) {
        let mut prev_syncd_shutdown = None;

        loop {
            // Is the nexthop shut down? We only set this to false when the
            // session is `Up`. Once a session becomes `Up`, the only valid
            // transition is to `Down`; we can freely move between `Down`,
            // `AdminDown`, and `Init` without modifying the RIB, and we only go
            // back to "not shut down" if we transition back to `Up`.
            let shutdown = match *self.state_rx.borrow_and_update() {
                BfdPeerState::Up => false,

                BfdPeerState::AdminDown
                | BfdPeerState::Down
                | BfdPeerState::Init => true,
            };

            // Only actually sync if we've had a change. (E.g., if the state
            // went from "down" to "init", we don't need to do anything, because
            // either way it's still shut down.)
            if Some(shutdown) != prev_syncd_shutdown {
                let sink = sink.clone();
                let nexthop = self.nexthop;
                let result = tokio::task::spawn_blocking(move || {
                    sink.set_nexthop_shutdown(nexthop, shutdown);
                })
                .await;

                if result.is_err() {
                    // `spawn_blocking` only fails if the runtime is shutting
                    // down, in which case there's nothing useful left to do.
                    return;
                }

                prev_syncd_shutdown = Some(shutdown);
            }

            // Wait for the next change. An error means the watch channel was
            // dropped, which means the session is being shut down.
            if self.state_rx.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wait_for_condition;
    use mg_common::lock;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::task::JoinHandle;

    const NEXTHOP_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    /// A `NexthopSink` that records every write, so tests can assert on the
    /// exact sequence of `(nexthop, shutdown)` updates the task performs.
    #[derive(Clone, Default)]
    struct RecordingSink(Arc<Mutex<Vec<(IpAddr, bool)>>>);

    impl NexthopSink for RecordingSink {
        fn set_nexthop_shutdown(&self, nexthop: IpAddr, shutdown: bool) {
            lock!(self.0).push((nexthop, shutdown));
        }
    }

    impl RecordingSink {
        fn writes(&self) -> Vec<(IpAddr, bool)> {
            lock!(self.0).clone()
        }
    }

    fn spawn_rib(
        initial: BfdPeerState,
    ) -> (watch::Sender<BfdPeerState>, RecordingSink, JoinHandle<()>) {
        let (tx, rx) = watch::channel(initial);
        let sink = RecordingSink::default();
        let handle =
            tokio::spawn(RibTask::new(NEXTHOP_IP, rx).run_impl(sink.clone()));
        (tx, sink, handle)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn initial_down_state_is_synced() {
        let (_tx, sink, _h) = spawn_rib(BfdPeerState::Down);
        wait_for_condition(Duration::from_secs(5), || {
            sink.writes() == [(NEXTHOP_IP, true)]
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_transitions_are_synced() {
        let (tx, sink, _h) = spawn_rib(BfdPeerState::Down);
        wait_for_condition(Duration::from_secs(5), || {
            sink.writes() == [(NEXTHOP_IP, true)]
        })
        .await
        .unwrap();

        tx.send_replace(BfdPeerState::Up);
        wait_for_condition(Duration::from_secs(5), || {
            sink.writes() == [(NEXTHOP_IP, true), (NEXTHOP_IP, false)]
        })
        .await
        .unwrap();

        tx.send_replace(BfdPeerState::Down);
        wait_for_condition(Duration::from_secs(5), || {
            sink.writes()
                == [(NEXTHOP_IP, true), (NEXTHOP_IP, false), (NEXTHOP_IP, true)]
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn redundant_shutdown_states_are_not_resynced() {
        // Down, Init, and AdminDown all map to "shut down"; after the initial
        // sync the task must not write again until the state leaves "down".
        let (tx, sink, _h) = spawn_rib(BfdPeerState::Down);
        wait_for_condition(Duration::from_secs(5), || {
            sink.writes() == [(NEXTHOP_IP, true)]
        })
        .await
        .unwrap();

        tx.send_replace(BfdPeerState::Init);
        tx.send_replace(BfdPeerState::AdminDown);

        // Give the task ample opportunity to (incorrectly) write again. A
        // correct task never writes here, so this is not racy for correct code.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(sink.writes(), [(NEXTHOP_IP, true)]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn exits_when_state_channel_closed() {
        let (tx, _sink, handle) = spawn_rib(BfdPeerState::Down);
        drop(tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("rib task did not exit after channel close")
            .expect("rib task panicked");
    }
}
