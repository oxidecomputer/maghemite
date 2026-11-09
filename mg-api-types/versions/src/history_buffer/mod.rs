// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Version `HISTORY_BUFFER` of the Maghemite Admin API.
//!
//! Splits BGP message history into `all` and `major` buffers, mirroring FSM
//! history, and replaces `FsmEventBuffer` with a `HistoryBufferSelector`
//! shared by the message and FSM history requests.

pub mod bgp;
