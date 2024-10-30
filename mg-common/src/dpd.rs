// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dpd_client::{types, Client, ClientState};
use std::time::Duration;

/// Create a new Dendrite/dpd client. The lower half always runs on the same
/// host/zone as the underlying platform.
pub fn new_client(log: &slog::Logger, tag: &str) -> Client {
    let client_state = ClientState {
        tag: tag.to_string(),
        log: log.clone(),
    };
    Client::new(
        &format!("http://localhost:{}", dpd_client::default_port()),
        client_state,
    )
}

/// Fetches the switch identifiers from the dpd client (API) in
/// relation to stats.
///
/// This spins indefinitely until the information is extracted.
pub async fn fetch_switch_identifiers(
    client: &Client,
    log: &slog::Logger,
) -> types::SwitchIdentifiers {
    loop {
        match client.switch_identifiers().await {
            Ok(resp) => {
                let idents = resp.into_inner();
                return idents;
            }
            Err(e) => {
                slog::error!(log,
                    "failed to fetch switch identifiers from dpd-client: {e:?}, will retry",
                )
            }
        }
        // Poll after a delay of 1 second
        const RETRY_INTERVAL: Duration = Duration::from_secs(1);
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}
