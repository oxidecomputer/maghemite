// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{HashMap, VecDeque};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::messages::{Message, PathAttributeDowngradeError};
use crate::v2::bgp::session::ConnectionId;
use crate::v11;

/// A message history entry is a BGP message with an associated timestamp and connection ID
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistoryEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: Message,
    pub connection_id: ConnectionId,
}

/// Message history for a BGP session
#[derive(Default, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MessageHistory {
    pub received: VecDeque<MessageHistoryEntry>,
    pub sent: VecDeque<MessageHistoryEntry>,
}

/// Unified message history response with string keys from PeerId Display
/// Keys will be "192.0.2.1" or "eth0" format
#[derive(Debug, Serialize, JsonSchema, Clone)]
pub struct MessageHistoryResponse {
    pub by_peer: HashMap<String, MessageHistory>,
}

impl TryFrom<MessageHistoryEntry> for v11::bgp::session::MessageHistoryEntry {
    type Error = PathAttributeDowngradeError;

    fn try_from(entry: MessageHistoryEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            timestamp: entry.timestamp,
            message: entry.message.try_into()?,
            connection_id: entry.connection_id,
        })
    }
}

impl TryFrom<MessageHistory> for v11::bgp::session::MessageHistory {
    type Error = PathAttributeDowngradeError;

    fn try_from(history: MessageHistory) -> Result<Self, Self::Error> {
        Ok(Self {
            received: history
                .received
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            sent: history
                .sent
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<MessageHistoryResponse>
    for v11::bgp::session::MessageHistoryResponse
{
    type Error = PathAttributeDowngradeError;

    fn try_from(r: MessageHistoryResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            by_peer: r
                .by_peer
                .into_iter()
                .map(|(k, v)| Ok((k, v.try_into()?)))
                .collect::<Result<_, Self::Error>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::messages::{
        OxideVtep, PathAttributeTypeCode, PathAttributeValue, UpdateMessage,
    };
    use super::*;

    #[test]
    fn history_downgrade_preserves_supported_messages_and_rejects_vtep() {
        let entry = |message| MessageHistoryEntry {
            timestamp: chrono::DateTime::UNIX_EPOCH,
            connection_id: ConnectionId::new(
                "192.0.2.1:179".parse().unwrap(),
                "192.0.2.2:12345".parse().unwrap(),
            ),
            message,
        };
        let history = MessageHistory {
            received: VecDeque::from([entry(Message::Update(UpdateMessage {
                path_attributes: vec![
                    PathAttributeValue::LocalPref(123).into(),
                ],
                ..Default::default()
            }))]),
            sent: VecDeque::from([entry(Message::KeepAlive)]),
        };
        let response = MessageHistoryResponse {
            by_peer: HashMap::from([("192.0.2.2".into(), history.clone())]),
        };
        let expected = serde_json::to_value(&response).unwrap();
        let downgraded =
            v11::bgp::session::MessageHistoryResponse::try_from(response)
                .unwrap();
        assert_eq!(serde_json::to_value(downgraded).unwrap(), expected);

        for received in [true, false] {
            let mut history = history.clone();
            let entries = if received {
                &mut history.received
            } else {
                &mut history.sent
            };
            entries.push_back(entry(Message::Update(UpdateMessage {
                path_attributes: vec![
                    PathAttributeValue::OxideVtep(
                        OxideVtep::new("rack-α".into()).unwrap(),
                    )
                    .into(),
                ],
                ..Default::default()
            })));
            let response = MessageHistoryResponse {
                by_peer: HashMap::from([("192.0.2.2".into(), history)]),
            };
            assert_eq!(
                v11::bgp::session::MessageHistoryResponse::try_from(response)
                    .unwrap_err(),
                PathAttributeDowngradeError {
                    type_code: PathAttributeTypeCode::OxideVtep
                },
            );
        }
    }
}
