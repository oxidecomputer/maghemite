// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::RouterStats, sm::SmContext};
use chrono::{DateTime, Utc};
use mg_common::nexus::{local_underlay_address, run_oximeter};
use omicron_common::api::internal::nexus::{ProducerEndpoint, ProducerKind};
use oximeter::{
    MetricsError, Producer, Sample,
    types::{Cumulative, ProducerRegistry},
};
use oximeter_producer::{ConfigLogging, ConfigLoggingLevel, LogConfig};
use slog::Logger;
use std::sync::atomic::Ordering;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use uuid::Uuid;

oximeter::use_timeseries!("ddm-session.toml");
pub use ddm_session::AdvertisementsReceived;
pub use ddm_session::AdvertisementsSent;
pub use ddm_session::DdmSession;
pub use ddm_session::ImportedTunnelEndpoints;
pub use ddm_session::ImportedUnderlayPrefixes;
pub use ddm_session::PeerAddressChanges;
pub use ddm_session::PeerExpirations;
pub use ddm_session::PeerSessionsEstablished;
pub use ddm_session::SolicitationsReceived;
pub use ddm_session::SolicitationsSent;
pub use ddm_session::UpdateSendFail;
pub use ddm_session::UpdatesReceived;
pub use ddm_session::UpdatesSent;

oximeter::use_timeseries!("ddm-router.toml");
pub use ddm_router::DdmRouter;
pub use ddm_router::OriginatedTunnelEndpoints;
pub use ddm_router::OriginatedUnderlayPrefixes;

#[derive(Clone)]
pub(crate) struct Stats {
    pub(crate) start_time: DateTime<Utc>,
    hostname: String,
    rack_id: Uuid,
    sled_id: Uuid,
    peers: Vec<SmContext>,
    router_stats: Arc<RouterStats>,
}

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
                datum: Cumulative::<u64>::with_start_time(
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
                datum: $value.load(Ordering::Relaxed),
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
                datum: $value.load(Ordering::Relaxed),
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
            self.hostname.clone().into(),
            self.rack_id,
            self.sled_id,
            OriginatedUnderlayPrefixes,
            self.router_stats.originated_underlay_prefixes
        ));

        samples.push(ddm_router_quantity!(
            self.hostname.clone().into(),
            self.rack_id,
            self.sled_id,
            OriginatedTunnelEndpoints,
            self.router_stats.originated_tunnel_endpoints
        ));

        for peer in &self.peers {
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                SolicitationsSent,
                peer.stats.solicitations_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                SolicitationsReceived,
                peer.stats.solicitations_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                AdvertisementsSent,
                peer.stats.advertisements_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                AdvertisementsReceived,
                peer.stats.advertisements_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                PeerExpirations,
                peer.stats.peer_expirations
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                PeerAddressChanges,
                peer.stats.peer_address_changes
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                PeerSessionsEstablished,
                peer.stats.peer_established
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                UpdatesSent,
                peer.stats.updates_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                UpdatesReceived,
                peer.stats.updates_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                UpdateSendFail,
                peer.stats.update_send_fail
            ));
            samples.push(ddm_session_quantity!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
                ImportedUnderlayPrefixes,
                peer.stats.imported_underlay_prefixes
            ));
            samples.push(ddm_session_quantity!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                peer.config.if_name.clone().into(),
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
        interval: Duration::from_secs(1),
    };
    let config = oximeter_producer::Config {
        server_info: producer_info,
        registration_address: None,
        log: log_config,
        default_request_body_max_bytes: 1024 * 1024 * 1024,
    };

    Ok(tokio::spawn(async move {
        run_oximeter(registry, config, log).await
    }))
}
