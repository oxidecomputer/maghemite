// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use mg_api_types::bfd::BfdPeerState;
use std::{num::NonZeroU8, sync::atomic::AtomicU64, time::Duration};

pub mod packet;

pub const COMPONENT_BFD: &str = "bfd";
pub const MOD_DAEMON: &str = "daemon";
pub const UNIT_PEER: &str = "peer";

pub const DEFAULT_BFD_TTL: u32 = 255;

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
pub struct PeerInfo {
    /// The interval at which the peer would _like_ to receive BFD control
    /// packets.
    pub desired_min_tx: Duration,

    /// This is the minimum interval between received BFD Control packets that
    /// this system is capable of supporting.
    pub required_min_rx: Duration,

    /// A unique identifer for the peer. This structure is used to keep track
    /// of remote peer information as well as our own. The remote peer
    /// generates their own discriminator. When a peer state machine is first
    /// started, we generate our discriminator with
    /// `PeerInfo::with_random_discriminator`
    pub discriminator: u32,

    /// Whether or not the peer is requesting demand mode. This means
    /// unsolicited BFD control packets will not be sent. The only control
    /// packets sent will be in response to control packets received with the
    /// poll flag set.
    pub demand_mode: bool,

    /// When multiplied against required_min_rx, defines the detection threshold
    /// connectivity status.
    ///
    /// RFC 5880 §6.8.6, a packet with a detect mult of 0 MUST be discarded; we
    /// encode that here via a `NonZero` type.
    pub detection_multiplier: NonZeroU8,
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
            // Three seems to be a common choice for other implementations.
            // Without intuition for or against this default, follow suit.
            detection_multiplier: NonZeroU8::new(3).expect("3 is not 0"),
        }
    }
}

impl PeerInfo {
    /// Initialize a peer info object with a random discriminator.
    pub fn with_random_discriminator(
        required_min_rx: Duration,
        detection_multiplier: NonZeroU8,
    ) -> Self {
        Self {
            required_min_rx,
            detection_multiplier,
            discriminator: rand::random(),
            ..Default::default()
        }
    }
}
