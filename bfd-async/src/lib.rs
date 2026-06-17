// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bfd::SessionMode;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroU8;

mod daemon;
mod dispatcher;
mod egress;
mod egress_src_port_iter;
mod rib;
mod session;
mod sm;

pub use daemon::Daemon;
pub use dispatcher::ListenerShutdownHandle;
pub use session::Session;

/// Errors from attempting to add a new BFD peer.
#[derive(Debug, thiserror::Error)]
pub enum AddPeerError {
    #[error("BFD peer {0} already exists")]
    PeerExists(IpAddr),

    #[error("failed to bind to {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        err: io::Error,
    },

    #[error("failed to set socket to nonblocking")]
    SetSocketNonBlocking(#[source] io::Error),

    #[error("failed to convert std socket to tokio socket")]
    StdToTokio(#[source] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("BFD detection threshold must be nonzero")]
pub struct DetectionThresholdZero;

pub struct AddPeerRequest {
    remote_addr: SocketAddr,
    listen_addr: SocketAddr,
    required_rx_micros: u64,
    detection_threshold: NonZeroU8,
    mode: SessionMode,
}

impl TryFrom<BfdPeerConfig> for AddPeerRequest {
    type Error = DetectionThresholdZero;

    fn try_from(value: BfdPeerConfig) -> Result<Self, Self::Error> {
        /// Port to be used for BFD multihop per RFC 5883.
        const BFD_MULTIHOP_PORT: u16 = 4784;
        /// Port to be used for BFD single per RFC 5881.
        const BFD_SINGLEHOP_PORT: u16 = 3784;

        let BfdPeerConfig {
            peer,
            listen,
            required_rx: required_rx_micros,
            detection_threshold,
            mode,
        } = value;

        let mode_port = match mode {
            SessionMode::SingleHop => BFD_SINGLEHOP_PORT,
            SessionMode::MultiHop => BFD_MULTIHOP_PORT,
        };

        let Some(detection_threshold) = NonZeroU8::new(detection_threshold)
        else {
            return Err(DetectionThresholdZero);
        };

        Ok(Self {
            remote_addr: SocketAddr::new(peer, mode_port),
            listen_addr: SocketAddr::new(listen, mode_port),
            required_rx_micros,
            detection_threshold,
            mode,
        })
    }
}

// Small helper used by multiple unit tests.
//
// This is a simpler version of omicron's `wait_for_condition()` - we don't
// accept a retry interval or any detailed status, which is fine for this crate.
#[cfg(test)]
async fn wait_for_condition(
    timeout: std::time::Duration,
    predicate: impl Fn() -> bool,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        if predicate() {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "timed out waiting for condition ({timeout:?})"
            ));
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
