// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v2::bgp::history::FsmEventBuffer;

/// Selects which history buffer to retrieve.
///
/// Each BGP session keeps its FSM event and message history in two rolling
/// buffers: one that records everything, and one that skips high-frequency
/// events so it retains significant events for longer.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HistoryBufferSelector {
    /// Every entry, including timer events and keepalives.
    All,
    /// Significant entries only. FSM history keeps state
    /// transitions, admin events and new connections; message history keeps
    /// every message except keepalives.
    Major,
}

impl From<FsmEventBuffer> for HistoryBufferSelector {
    fn from(buffer: FsmEventBuffer) -> Self {
        match buffer {
            FsmEventBuffer::All => Self::All,
            FsmEventBuffer::Major => Self::Major,
        }
    }
}
