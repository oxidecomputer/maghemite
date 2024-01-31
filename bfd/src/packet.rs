// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::BfdPeerState;
use anyhow::{anyhow, Result};

// Control packet flags.
const POLL: u8 = 1 << 5;
const FINAL: u8 = 1 << 4;
const CONTROL_PLANE_INDEPENDENT: u8 = 1 << 3;
const AUTHENTICATION_PRESENT: u8 = 1 << 2;
const DEMAND: u8 = 1 << 1;
const MULTIPOINT: u8 = 1;

/// The BFD control packet. The commentary on this structure comes directly from
/// the RFC with light editing.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       My Discriminator                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Your Discriminator                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Desired Min TX Interval                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Required Min RX Interval                    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Required Min Echo RX Interval                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// An optional Authentication Section MAY be present:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Auth Type   |   Auth Len    |    Authentication Data...     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct Control {
    /// This field contains both the version and the diagnostic code.
    ///
    /// The version number of the protocol. RFC 5880 defines protocol version 1.
    ///
    /// The diagnostic specified the local system's reason for the last change
    /// in session state.  Values are:
    ///
    /// 0. No Diagnostic
    /// 1. Control Detection Time Expired
    /// 2. Echo Function Failed
    /// 3. Neighbor Signaled Session Down
    /// 4. Forwarding Plane Reset
    /// 5. Path Down
    /// 6. Concatenated Path Down
    /// 7. Administratively Down
    /// 8. Reverse Concatenated Path Down
    /// 9-31. -- Reserved for future use
    ///
    pub vers_diag: u8,

    /// This field contains both the status and flag values.
    ///
    /// The status is the current BFD session state as seen by the transmitting
    /// system. Its values are:
    ///
    /// 0. AdminDown
    /// 1. Down
    /// 2. Init
    /// 3. Up
    ///
    /// The remaining bits are binary values as follows.
    ///
    /// Poll (P)
    ///
    ///   If set, the transmitting system is requesting verification of
    ///   connectivity, or of a parameter change, and is expecting a packet with
    ///   the Final (F) bit in reply. If clear, the transmitting system is not
    ///   requesting verification.
    ///
    /// Final (F)
    ///
    ///   If set, the transmitting system is responding to a received BFD
    ///   Control packet that had the Poll (P) bit set.  If clear, the
    ///   transmitting system is not responding to a Poll.
    ///
    /// Control Plane Independent (C)
    ///
    ///   If set, the transmitting system's BFD implementation does not share
    ///   fate with its control plane (in other words, BFD is implemented in the
    ///   forwarding plane and can continue to function through disruptions in
    ///   the control plane). If clear, the transmitting system's BFD
    ///   implementation shares fate with its control plane.
    ///
    ///   The use of this bit is application dependent and is outside the scope
    ///   of RFC 5880.
    ///
    /// Demand (D)
    ///
    ///   If set, Demand mode is active in the transmitting system (the system
    ///   wishes to operate in Demand mode, knows that the session is Up in both
    ///   directions, and is directing the remote system to cease the periodic
    ///   transmission of BFD Control packets). If clear, Demand mode is not
    ///   active in the transmitting system.
    ///
    /// Multipoint (M)
    ///
    ///   This bit is reserved for future point-to-multipoint extensions to BFD.
    ///   It MUST be zero on both transmit and receipt.
    pub flags: u8,

    /// Detection time multiplier. The negotiated transmit interval, multiplied
    /// by this value, provides the Detection Time for the receiving system in
    /// Asynchronous mode.
    pub detect_mult: u8,

    /// Length of the BFD Control packet, in bytes.
    pub length: u8,

    /// A unique, nonzero discriminator value generated by the transmitting
    /// system, used to demultiplex multiple BFD sessions between the same pair
    /// of systems.
    pub my_discriminator: u32,

    /// The discriminator received from the corresponding remote system.  This
    /// field reflects back the received value of My Discriminator, or is zero
    /// if that value is unknown.
    pub your_discriminator: u32,

    /// This is the minimum interval, in microseconds, that the local system
    /// would like to use when transmitting BFD Control packets, less any jitter
    /// applied. The value zero is reserved.
    pub desired_min_tx: u32,

    /// This is the minimum interval, in microseconds, between received BFD
    /// Control packets that this system is capable of supporting, less any
    /// jitter applied by the sender. If this value is zero, the transmitting
    /// system does not want the remote system to send any periodic BFD Control
    /// packets.
    pub required_min_rx: u32,

    /// This is the minimum interval, in microseconds, between received BFD Echo
    /// packets that this system is capable of supporting, less any jitter
    /// applied by the sender. If this value is zero, the transmitting system
    /// does not support the receipt of BFD Echo packets.
    pub required_min_echo_rx: u32,

    pub auth: Option<Auth>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            // per the RFC, version is always 1
            vers_diag: 1 << 5,
            // default state machine state is down
            flags: BfdPeerState::Down.wire_format(),
            // default to detection threshold multipler of 3
            detect_mult: 3,
            // 24 is sans auth, if using auth recompute
            length: 24,
            my_discriminator: 0,
            your_discriminator: 0,
            desired_min_tx: 0,
            required_min_rx: 0,
            required_min_echo_rx: 0,
            auth: None,
        }
    }
}

impl Control {
    /// Deserialize an array of bytes as a `Control`.
    pub fn from_bytes(d: &[u8]) -> Result<Self> {
        if d.len() < 24 {
            return Err(anyhow!("control packet too small"));
        }
        Ok(Self {
            vers_diag: d[0],
            flags: d[1],
            detect_mult: d[2],
            length: d[3],
            my_discriminator: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
            your_discriminator: u32::from_be_bytes([d[8], d[9], d[10], d[11]]),
            desired_min_tx: u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
            required_min_rx: u32::from_be_bytes([d[16], d[17], d[18], d[19]]),
            required_min_echo_rx: u32::from_be_bytes([
                d[20], d[21], d[22], d[23],
            ]),
            auth: None,
        })
    }

    /// Serialize a `Control` as vector of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v =
            vec![self.vers_diag, self.flags, self.detect_mult, self.length];
        v.extend_from_slice(&self.my_discriminator.to_be_bytes());
        v.extend_from_slice(&self.your_discriminator.to_be_bytes());
        v.extend_from_slice(&self.desired_min_tx.to_be_bytes());
        v.extend_from_slice(&self.required_min_rx.to_be_bytes());
        v.extend_from_slice(&self.required_min_echo_rx.to_be_bytes());
        v
    }

    /// Get the state from the control packet.
    pub fn state(&self) -> State {
        let status = (self.flags & 0b11000000) >> 6;
        match BfdPeerState::try_from(status) {
            Ok(s) => State::Peer(s),
            Err(_) => State::Unknown(status),
        }
    }

    /// Set control packet state.
    pub fn set_state(&mut self, ps: BfdPeerState) {
        self.flags = (self.flags & 0b00111111) | ((ps as u8) << 6);
    }

    /// Returns true of the poll flag is set.
    pub fn poll(&self) -> bool {
        (self.flags & POLL) != 0
    }

    /// Set the poll flag to true.
    pub fn set_poll(&mut self) {
        self.flags |= POLL;
    }

    /// Set the poll flag to false.
    pub fn clear_poll(&mut self) {
        self.flags &= !POLL;
    }

    /// Returns true if the final flag is set.
    pub fn r#final(&self) -> bool {
        (self.flags & FINAL) != 0
    }

    /// Set the final flag to true.
    pub fn set_final(&mut self) {
        self.flags |= FINAL;
    }

    /// Set the final flag to false.
    pub fn clear_final(&mut self) {
        self.flags &= !FINAL;
    }

    /// Returns true if the control plane independent flag is set.
    pub fn control_plane_independent(&self) -> bool {
        (self.flags & CONTROL_PLANE_INDEPENDENT) != 0
    }

    /// Set the control plane independent flag to true.
    pub fn set_control_plane_independent(&mut self) {
        self.flags |= CONTROL_PLANE_INDEPENDENT;
    }

    /// Set the control plane independent flag to false.
    pub fn clear_control_plane_independent(&mut self) {
        self.flags &= !CONTROL_PLANE_INDEPENDENT;
    }

    /// Returns true if the authentication present flag is set to true.
    pub fn authentication_present(&self) -> bool {
        (self.flags & AUTHENTICATION_PRESENT) != 0
    }

    /// Sets the authentication present flag to true.
    pub fn set_authentication_present(&mut self) {
        self.flags |= AUTHENTICATION_PRESENT;
    }

    /// Sets the authentication present flag to false.
    pub fn clear_authentication_present(&mut self) {
        self.flags &= !AUTHENTICATION_PRESENT;
    }

    /// Returns true if the demand mode flag is set.
    pub fn demand(&self) -> bool {
        (self.flags & DEMAND) != 0
    }

    /// Set the demand mode flag to true.
    pub fn set_demand(&mut self) {
        self.flags |= DEMAND;
    }

    /// Set the demand mode flag to false.
    pub fn clear_demand(&mut self) {
        self.flags &= !DEMAND;
    }

    /// Returns true if the multipoint flag is set.
    pub fn multipoint(&self) -> bool {
        (self.flags & MULTIPOINT) != 0
    }

    /// Set the multipoint flag to true.
    pub fn set_multipoint(&mut self) {
        self.flags |= MULTIPOINT;
    }

    /// Set the multipoint flag to false.
    pub fn clear_multipoint(&mut self) {
        self.flags &= !MULTIPOINT;
    }
}

/// A wrapper for BfdPeerState that can handle unknown states.
pub enum State {
    Peer(BfdPeerState),
    Unknown(u8),
}

impl crate::BfdPeerState {
    /// A helper function to transition between enumm and wire representations
    /// for peer states.
    fn wire_format(&self) -> u8 {
        (*self as u8) << 6
    }
}

/// An optional authentication section for BFD control packets.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Auth Type   |   Auth Len    |    Authentication Data...     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct Auth {
    /// The authentication type in use, if the Authentication Present (A) bit is
    /// set.
    ///
    /// 0. Reserved
    /// 1. Simple Password
    /// 2. Keyed MD5
    /// 3. Meticulous Keyed MD5
    /// 4. Keyed SHA1
    /// 5. Meticulous Keyed SHA1
    /// 6-255. Reserved for future use
    ///
    pub auth_type: u8,

    /// The length, in bytes, of the authentication section, including the Auth
    /// Type and Auth Len fields.
    pub auth_len: u8,

    /// Underlying authentication data.
    pub auth_data: AuthData,
}

#[derive(Debug, Clone)]
pub enum AuthData {
    /// Password authentication packet content.
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Sequence Number                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                      Auth Key/Digest...                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                              ...                              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    Password {
        /// The authentication key ID in use for this packet. This allows
        /// multiple keys to be active simultaneously.
        auth_key_id: u8,

        /// The simple password in use on this session. The password is a binary
        /// string, and MUST be from 1 to 16 bytes in length. The password MUST
        /// be encoded and configured according to section 6.7.2 of RFC 5880.
        password: Vec<u8>,
    },

    /// The use of MD5-based authentication is strongly discouraged. However,
    /// it is documented here for compatibility with existing implementations.
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Sequence Number                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                       Auth Key/Hash...                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                              ...                              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    KeyedMd5 {
        /// The authentication key ID in use for this packet. This allows
        /// multiple keys to be active simultaneously.
        auth_key_id: u8,

        /// This byte MUST be set to zero on transmit, and ignored on receipt.
        reserved: u8,

        /// The sequence number for this packet. For Keyed MD5 Authentication,
        /// this value is incremented occasionally. For Meticulous Keyed MD5
        /// Authentication, this value is incremented for each successive packet
        /// transmitted for a session. This provides protection against replay
        /// attacks.
        sequence_number: u32,

        /// This field carries the 16-byte MD5 digest for the packet. When the
        /// digest is calculated, the shared MD5 key is stored in this field,
        /// padded to 16 bytes with trailing zero bytes if needed. The shared
        /// key MUST be encoded and configured to section 6.7.3 in RFC 5880.
        key: Vec<u8>,
    },

    /// Keyed SHA1 and Meticulous Keyed SHA1 Authentication packet content.
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Sequence Number                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                       Auth Key/Hash...                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                              ...                              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    KeyedSha1 {
        /// The authentication key ID in use for this packet. This allows
        /// multiple keys to be active simultaneously.
        auth_key_id: u8,

        /// This byte MUST be set to zero on transmit and ignored on receipt.
        reserved: u8,

        /// The sequence number for this packet. For Keyed SHA1 Authentication,
        /// this value is incremented occasionally. For Meticulous Keyed SHA1
        /// Authentication, this value is incremented for each successive packet
        /// transmitted for a session. This provides protection against replay
        /// attacks.
        sequence_number: u32,

        /// This field carries the 20-byte SHA1 hash for the packet. When the
        /// hash is calculated, the shared SHA1 key is stored in this field,
        /// padded to a length of 20 bytes with trailing zero bytes if needed.
        /// The shared key MUST be encoded and configured to section 6.7.4.
        key: Vec<u8>,
    },
}
