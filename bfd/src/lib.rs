// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use mg_api_types::bfd::BfdPeerConfig;
use mg_api_types::bfd::SessionMode;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

mod daemon;
mod dispatcher;
mod egress;
mod egress_src_port_iter;
mod rib;
mod session;
mod sm;

pub mod packet;
pub use daemon::Daemon;
pub use dispatcher::ListenerShutdownHandle;
pub use session::Session;

const COMPONENT_BFD: &str = "bfd";
const MOD_DAEMON: &str = "daemon";
const UNIT_PEER: &str = "peer";

const DEFAULT_BFD_TTL: u32 = 255;

/// Default detection threshold multiplier.
///
/// Three seems to be a common choice for other implementations. Without
/// intuition for or against this default, follow suit.
const DEFAULT_DETECT_MULTIPLIER: NonZeroU8 = NonZeroU8::new(3).unwrap();

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

impl From<BfdPeerConfig> for AddPeerRequest {
    fn from(value: BfdPeerConfig) -> Self {
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

        Self {
            remote_addr: SocketAddr::new(peer, mode_port),
            listen_addr: SocketAddr::new(listen, mode_port),
            required_rx_micros,
            detection_threshold,
            mode,
        }
    }
}

#[derive(Default)]
pub struct SessionCounters {
    pub control_packets_sent: AtomicU64,
    pub control_packet_send_failures: AtomicU64,
    pub control_packets_received: AtomicU64,
    pub admin_down_status_received: AtomicU64,
    pub down_status_received: AtomicU64,
    pub init_status_received: AtomicU64,
    pub up_status_received: AtomicU64,
    pub unknown_status_received: AtomicU64,
    pub transition_to_init: AtomicU64,
    pub transition_to_down: AtomicU64,
    pub transition_to_up: AtomicU64,
    pub timeout_expired: AtomicU64,
    pub message_receive_error: AtomicU64,
    pub unexpected_message: AtomicU64,
}

/// Information about a BFD peer.
#[derive(Debug, Clone, Copy)]
struct PeerInfo {
    /// The interval at which the peer would _like_ to receive BFD control
    /// packets.
    desired_min_tx: Duration,

    /// This is the minimum interval between received BFD Control packets that
    /// this system is capable of supporting.
    required_min_rx: Duration,

    /// A unique identifer for the peer. This structure is used to keep track
    /// of remote peer information as well as our own. The remote peer
    /// generates their own discriminator. When a peer state machine is first
    /// started, we generate our discriminator with
    /// `PeerInfo::with_random_discriminator`
    discriminator: u32,

    /// Whether or not the peer is requesting demand mode. This means
    /// unsolicited BFD control packets will not be sent. The only control
    /// packets sent will be in response to control packets received with the
    /// poll flag set.
    demand_mode: bool,

    /// When multiplied against required_min_rx, defines the detection threshold
    /// connectivity status.
    ///
    /// RFC 5880 §6.8.6, a packet with a detect mult of 0 MUST be discarded; we
    /// encode that here via a `NonZero` type.
    detection_multiplier: NonZeroU8,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            // Try to pick a sane default to start with. One second seems
            // prudent.
            desired_min_tx: Duration::from_secs(1),
            required_min_rx: Duration::from_secs(1),
            discriminator: 0,
            demand_mode: false,
            detection_multiplier: DEFAULT_DETECT_MULTIPLIER,
        }
    }
}

impl PeerInfo {
    /// Initialize a peer info object with a random discriminator.
    fn with_random_discriminator(
        required_min_rx: Duration,
        detection_multiplier: NonZeroU8,
    ) -> Self {
        Self {
            required_min_rx,
            detection_multiplier,
            discriminator: rand::random(), ..Default::default()
        }
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
