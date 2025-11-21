// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use backoff::{
    Error as BackoffError, ExponentialBackoff, future::retry_notify,
};
use slog::{Logger, warn};
use std::net::IpAddr;
use std::time::Duration;

/// Returns an aggressive retry policy for internal services.
/// Retries forever with exponential backoff starting at 100ms, maxing at 10s.
fn retry_policy_internal_service_aggressive() -> ExponentialBackoff {
    ExponentialBackoff {
        initial_interval: Duration::from_millis(100),
        max_interval: Duration::from_secs(10),
        max_elapsed_time: None, // Retry forever
        multiplier: 2.0,
        ..Default::default()
    }
}

pub async fn run_oximeter(
    registry: oximeter::types::ProducerRegistry,
    config: oximeter_producer::Config,
    log: Logger,
) {
    let op = || async {
        oximeter_producer::Server::with_registry(registry.clone(), &config)
            .map_err(|e| BackoffError::transient(e.to_string()))
    };

    let log_failure = |e, delay| {
        warn!(log, "stats server not created yet, {e} waiting {delay:?}");
    };

    let server = retry_notify(
        retry_policy_internal_service_aggressive(),
        op,
        log_failure,
    )
    .await;

    if let Ok(server) = server {
        server.serve_forever().await.expect("metrics server failed");
    }
}

#[cfg(target_os = "illumos")]
pub fn local_underlay_address() -> anyhow::Result<IpAddr> {
    let local_addrs = libnet::get_ipaddrs()?;
    for addrs in local_addrs.values() {
        for info in addrs {
            let aobj_name = info.obj()?.0;
            if aobj_name.ends_with("omicron6") || aobj_name.ends_with("sled6") {
                return Ok(info.addr);
            }
        }
    }
    Err(anyhow::anyhow!("underlay address not found"))
}

#[cfg(not(target_os = "illumos"))]
pub fn local_underlay_address() -> anyhow::Result<IpAddr> {
    Ok(std::net::Ipv6Addr::UNSPECIFIED.into())
}
