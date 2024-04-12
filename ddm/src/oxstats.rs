// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::RouterStats, sm::SmContext};
use chrono::{DateTime, Utc};
use dropshot::{ConfigLogging, ConfigLoggingLevel};
use mg_common::{
    counter,
    nexus::{local_underlay_address, resolve_nexus, run_oximeter},
    quantity,
};
use omicron_common::api::internal::nexus::{ProducerEndpoint, ProducerKind};
use oximeter::{
    types::{Cumulative, ProducerRegistry},
    Metric, MetricsError, Producer, Sample, Target,
};
use oximeter_producer::LogConfig;
use slog::Logger;
use std::sync::atomic::Ordering;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct Stats {
    pub(crate) start_time: DateTime<Utc>,
    hostname: String,
    rack_id: Uuid,
    sled_id: Uuid,
    peers: Vec<SmContext>,
    router_stats: Arc<RouterStats>,
}

#[derive(Debug, Clone, Target)]
struct DdmSession {
    hostname: String,
    rack_id: Uuid,
    sled_id: Uuid,
    interface: String,
}

#[derive(Debug, Clone, Target)]
struct DdmRouter {
    hostname: String,
    rack_id: Uuid,
    sled_id: Uuid,
}

counter!(SolicitationsSent);
counter!(SolicitationsReceived);
counter!(AdvertisementsSent);
counter!(AdvertisementsReceived);
counter!(PeerExpirations);
counter!(PeerAddressChanges);
counter!(PeerSessionsEstablished);
counter!(UpdatesSent);
counter!(UpdatesReceived);
counter!(UpdateSendFail);
quantity!(ImportedUnderlayPrefixes, u64);
quantity!(ImportedTunnelEndpoints, u64);
quantity!(OriginatedUnderlayPrefixes, u64);
quantity!(OriginatedTunnelEndpoints, u64);

macro_rules! ddm_session_counter {
    (
        $start_time:expr,
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $interface:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &DdmSession {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
                interface: $interface,
            },
            &$kind {
                count: Cumulative::<u64>::with_start_time(
                    $start_time,
                    $value.load(Ordering::Relaxed),
                ),
            },
        )?
    };
}

macro_rules! ddm_session_quantity {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $interface:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &DdmSession {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
                interface: $interface,
            },
            &$kind {
                quantity: $value.load(Ordering::Relaxed),
            },
        )?
    };
}

macro_rules! ddm_router_quantity {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &DdmRouter {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
            },
            &$kind {
                quantity: $value.load(Ordering::Relaxed),
            },
        )?
    };
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stats")
    }
}

impl Producer for Stats {
    fn produce(
        &mut self,
    ) -> Result<Box<dyn Iterator<Item = Sample>>, MetricsError> {
        // Capacity is for number of router level stats plus number session
        // level stats.
        let mut samples: Vec<Sample> = Vec::with_capacity(2 + 13);

        samples.push(ddm_router_quantity!(
            self.hostname.clone(),
            self.rack_id,
            self.sled_id,
            OriginatedUnderlayPrefixes,
            self.router_stats.originated_underlay_prefixes
        ));

        samples.push(ddm_router_quantity!(
            self.hostname.clone(),
            self.rack_id,
            self.sled_id,
            OriginatedTunnelEndpoints,
            self.router_stats.originated_tunnel_endpoints
        ));

        for peer in &self.peers {
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                SolicitationsSent,
                peer.stats.solicitations_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                SolicitationsReceived,
                peer.stats.solicitations_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                AdvertisementsSent,
                peer.stats.advertisements_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                AdvertisementsReceived,
                peer.stats.advertisements_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                PeerExpirations,
                peer.stats.peer_expirations
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                PeerAddressChanges,
                peer.stats.peer_address_changes
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                PeerSessionsEstablished,
                peer.stats.peer_established
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                UpdatesSent,
                peer.stats.updates_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                UpdatesReceived,
                peer.stats.updates_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                UpdateSendFail,
                peer.stats.update_send_fail
            ));
            samples.push(ddm_session_quantity!(
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                ImportedUnderlayPrefixes,
                peer.stats.imported_underlay_prefixes
            ));
            samples.push(ddm_session_quantity!(
                self.hostname.clone(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone(),
                ImportedTunnelEndpoints,
                peer.stats.imported_tunnel_endpoints
            ));
        }

        Ok(Box::new(samples.into_iter()))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start_server(
    port: u16,
    peers: Vec<SmContext>,
    router_stats: Arc<RouterStats>,
    dns_servers: Vec<SocketAddr>,
    hostname: String,
    rack_id: Uuid,
    sled_id: Uuid,
    log: Logger,
) -> anyhow::Result<JoinHandle<()>> {
    let addr = local_underlay_address()?;
    let sa = SocketAddr::new(addr, port);
    let log_config = LogConfig::Config(ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Debug,
    });
    let registry = ProducerRegistry::new();

    let stats_producer = Stats {
        start_time: chrono::offset::Utc::now(),
        peers,
        hostname,
        rack_id,
        sled_id,
        router_stats,
    };

    registry.register_producer(stats_producer).unwrap();
    let producer_info = ProducerEndpoint {
        id: registry.producer_id(),
        kind: ProducerKind::Service,
        address: sa,
        base_route: "/collect".to_string(),
        interval: Duration::from_secs(1),
    };

    Ok(tokio::spawn(async move {
        let nexus_addr = resolve_nexus(log.clone(), &dns_servers).await;
        let config = oximeter_producer::Config {
            server_info: producer_info,
            registration_address: Some(nexus_addr),
            log: log_config,
            request_body_max_bytes: 1024 * 1024 * 1024,
        };
        run_oximeter(registry.clone(), config.clone(), log.clone()).await
    }))
}
