// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use internal_dns::{resolver::Resolver, ServiceName};
use slog::{info, warn, Logger};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::time::sleep;

pub async fn resolve_nexus(
    log: Logger,
    dns_servers: &[SocketAddr],
) -> SocketAddr {
    info!(log, "resolving nexus");
    loop {
        let resolver = match Resolver::new_from_addrs(log.clone(), dns_servers)
        {
            Ok(resolver) => resolver,
            Err(e) => {
                warn!(log, "creating nexus resolver failed, waiting 1s: {e}");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let op = || async {
            match resolver.lookup_socket_v6(ServiceName::Nexus).await {
                Ok(addr) => Ok(addr),
                Err(e) => Err(e.into()),
            }
        };

        let log_failure = |e, delay| {
            warn!(log, "resolving nexus failed, {e} waiting {delay:?}");
        };

        match omicron_common::backoff::retry_notify(
            omicron_common::backoff::retry_policy_internal_service_aggressive(),
            op,
            log_failure,
        )
        .await
        {
            Ok(addr) => return addr.into(),
            Err(e) => {
                warn!(log, "error resulving nexus: {e}");
            }
        }
    }
}

pub async fn run_oximeter(
    registry: oximeter::types::ProducerRegistry,
    config: oximeter_producer::Config,
    log: Logger,
) {
    let op = || async {
        match oximeter_producer::Server::with_registry(
            registry.clone(),
            &config,
        )
        .await
        {
            Ok(s) => Ok(s),
            Err(e) => {
                if let oximeter_producer::Error::RegistrationError {
                    retryable,
                    msg: _,
                } = &e
                {
                    if !retryable {
                        return Err(backoff::Error::Permanent(e));
                    }
                }
                Err(e.into())
            }
        }
    };

    let log_failure = |e, delay| {
        warn!(log, "stats server not created yet, {e} waiting {delay:?}");
    };

    let server = omicron_common::backoff::retry_notify(
        omicron_common::backoff::retry_policy_internal_service_aggressive(),
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
