// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{admin::RouterStats, sm::SmContext};
use chrono::{DateTime, Utc};
use dpd_client::types;
use mg_common::nexus::{local_underlay_address, run_oximeter};
use omicron_common::api::internal::{
    nexus::{ProducerEndpoint, ProducerKind},
    shared::SledIdentifiers,
};
use oximeter::{
    types::{Cumulative, ProducerRegistry},
    MetricsError, Producer, Sample,
};
use oximeter_producer::{ConfigLogging, ConfigLoggingLevel, LogConfig};
use slog::Logger;
use std::sync::atomic::Ordering;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;

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

/// Tag used for managing ddm.
const DDMD_TAG: &str = "ddmd";

#[derive(Clone)]
pub(crate) struct Stats {
    pub(crate) start_time: DateTime<Utc>,
    hostname: String,
    sled_idents: SledIdentifiers,
    switch_idents: types::SwitchIdentifiers,
    peers: Vec<SmContext>,
    router_stats: Arc<RouterStats>,
}

macro_rules! ddm_session_counter {
    (
        $start_time:expr,
        $hostname:expr,
        $sled_idents:expr,
        $switch_idents:expr,
        $interface:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &DdmSession {
                hostname: $hostname,
                interface: $interface,
                rack_id: $sled_idents.rack_id,
                sled_id: $sled_idents.sled_id,
                sled_model: $sled_idents.model.clone().into(),
                sled_revision: $sled_idents.revision,
                sled_serial: $sled_idents.serial.clone().into(),
                switch_id: $switch_idents.sidecar_id,
                switch_model: $switch_idents.model.clone().into(),
                switch_revision: $switch_idents.revision,
                switch_serial: $switch_idents.serial.clone().into(),
                switch_slot: $switch_idents.slot,
                asic_fab: $switch_idents
                    .fab
                    .clone()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| $switch_idents.asic_backend.to_string())
                    .into(),
                asic_lot: $switch_idents
                    .lot
                    .clone()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| $switch_idents.asic_backend.to_string())
                    .into(),
                asic_wafer: $switch_idents.wafer.unwrap_or(0),
                asic_wafer_loc_x: $switch_idents
                    .wafer_loc
                    .map(|[x, _]| x)
                    .unwrap_or(0),
                asic_wafer_loc_y: $switch_idents
                    .wafer_loc
                    .map(|[_, y]| y)
                    .unwrap_or(0),
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
        $sled_idents:expr,
        $switch_idents:expr,
        $interface:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &DdmSession {
                hostname: $hostname,
                interface: $interface,
                rack_id: $sled_idents.rack_id,
                sled_id: $sled_idents.sled_id,
                sled_model: $sled_idents.model.clone().into(),
                sled_revision: $sled_idents.revision,
                sled_serial: $sled_idents.serial.clone().into(),
                switch_id: $switch_idents.sidecar_id,
                switch_model: $switch_idents.model.clone().into(),
                switch_revision: $switch_idents.revision,
                switch_serial: $switch_idents.serial.clone().into(),
                switch_slot: $switch_idents.slot,
                asic_fab: $switch_idents
                    .fab
                    .clone()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| $switch_idents.asic_backend.to_string())
                    .into(),
                asic_lot: $switch_idents
                    .lot
                    .clone()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| $switch_idents.asic_backend.to_string())
                    .into(),
                asic_wafer: $switch_idents.wafer.unwrap_or(0),
                asic_wafer_loc_x: $switch_idents
                    .wafer_loc
                    .map(|[x, _]| x)
                    .unwrap_or(0),
                asic_wafer_loc_y: $switch_idents
                    .wafer_loc
                    .map(|[_, y]| y)
                    .unwrap_or(0),
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
        $sled_idents:expr,
        $switch_idents:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &DdmRouter {
                hostname: $hostname,
                rack_id: $sled_idents.rack_id,
                sled_id: $sled_idents.sled_id,
                sled_model: $sled_idents.model.clone().into(),
                sled_revision: $sled_idents.revision,
                sled_serial: $sled_idents.serial.clone().into(),
                switch_id: $switch_idents.sidecar_id,
                switch_model: $switch_idents.model.clone().into(),
                switch_revision: $switch_idents.revision,
                switch_serial: $switch_idents.serial.clone().into(),
                switch_slot: $switch_idents.slot,
                asic_fab: $switch_idents
                    .fab
                    .clone()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| $switch_idents.asic_backend.to_string())
                    .into(),
                asic_lot: $switch_idents
                    .lot
                    .clone()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| $switch_idents.asic_backend.to_string())
                    .into(),
                asic_wafer: $switch_idents.wafer.unwrap_or(0),
                asic_wafer_loc_x: $switch_idents
                    .wafer_loc
                    .map(|[x, _]| x)
                    .unwrap_or(0),
                asic_wafer_loc_y: $switch_idents
                    .wafer_loc
                    .map(|[_, y]| y)
                    .unwrap_or(0),
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
            self.sled_idents,
            self.switch_idents,
            OriginatedUnderlayPrefixes,
            self.router_stats.originated_underlay_prefixes
        ));

        samples.push(ddm_router_quantity!(
            self.hostname.clone().into(),
            self.sled_idents,
            self.switch_idents,
            OriginatedTunnelEndpoints,
            self.router_stats.originated_tunnel_endpoints
        ));

        for peer in &self.peers {
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                SolicitationsSent,
                peer.stats.solicitations_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                SolicitationsReceived,
                peer.stats.solicitations_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                AdvertisementsSent,
                peer.stats.advertisements_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                AdvertisementsReceived,
                peer.stats.advertisements_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                PeerExpirations,
                peer.stats.peer_expirations
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                PeerAddressChanges,
                peer.stats.peer_address_changes
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                PeerSessionsEstablished,
                peer.stats.peer_established
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                UpdatesSent,
                peer.stats.updates_sent
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                UpdatesReceived,
                peer.stats.updates_received
            ));
            samples.push(ddm_session_counter!(
                self.start_time,
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                UpdateSendFail,
                peer.stats.update_send_fail
            ));
            samples.push(ddm_session_quantity!(
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                ImportedUnderlayPrefixes,
                peer.stats.imported_underlay_prefixes
            ));
            samples.push(ddm_session_quantity!(
                self.hostname.clone().into(),
                self.sled_idents,
                self.switch_idents,
                peer.config.if_name.clone().into(),
                ImportedTunnelEndpoints,
                peer.stats.imported_tunnel_endpoints
            ));
        }

        Ok(Box::new(samples.into_iter()))
    }
}

pub fn start_server(
    port: u16,
    peers: Vec<SmContext>,
    router_stats: Arc<RouterStats>,
    hostname: String,
    sled_idents: SledIdentifiers,
    log: Logger,
) -> anyhow::Result<JoinHandle<()>> {
    let addr = local_underlay_address()?;
    let sa = SocketAddr::new(addr, port);
    let log_config = LogConfig::Config(ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Debug,
    });
    let _handle = tokio::spawn(async move {
        let client = mg_common::dpd::new_client(&log, DDMD_TAG);
        let switch_idents =
            mg_common::dpd::fetch_switch_identifiers(&client, &log).await;

        let registry = ProducerRegistry::new();
        let stats_producer = Stats {
            start_time: chrono::offset::Utc::now(),
            peers,
            hostname,
            sled_idents,
            switch_idents,
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

        run_oximeter(registry, config, log).await
    });

    Ok(_handle)
}
