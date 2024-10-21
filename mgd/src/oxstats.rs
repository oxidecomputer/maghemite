// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::admin::HandlerContext;
use crate::bfd_admin::BfdContext;
use crate::bgp_admin::BgpContext;
use chrono::{DateTime, Utc};
use mg_common::lock;
use mg_common::nexus::{local_underlay_address, run_oximeter};
use mg_common::stats::MgLowerStats;
use omicron_common::api::internal::nexus::{ProducerEndpoint, ProducerKind};
use oximeter::types::{Cumulative, ProducerRegistry};
use oximeter::{MetricsError, Producer, Sample};
use oximeter_producer::{ConfigLogging, ConfigLoggingLevel, LogConfig};
use rdb::Db;
use slog::{warn, Logger};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use uuid::Uuid;

oximeter::use_timeseries!("bfd-session.toml");
use bfd_session::BfdSession;
use bfd_session::ControlPacketSendFailures;
use bfd_session::ControlPacketsReceived;
use bfd_session::ControlPacketsSent;
use bfd_session::MessageReceiveError;
use bfd_session::TimeoutExpired;
use bfd_session::TransitionToDown;
use bfd_session::TransitionToInit;
use bfd_session::TransitionToUp;

oximeter::use_timeseries!("bgp-session.toml");
use bgp_session::ActiveConnectionsAccepted;
use bgp_session::BgpSession;
use bgp_session::ConnectionRetries;
use bgp_session::HoldTimerExpirations;
use bgp_session::IdleHoldTimerExpirations;
use bgp_session::KeepaliveSendFailures;
use bgp_session::KeepalivesReceived;
use bgp_session::KeepalivesSent;
use bgp_session::NotificationSendFailures;
use bgp_session::OpenHandleFailures;
use bgp_session::OpenSendFailures;
use bgp_session::OpensReceived;
use bgp_session::OpensSent;
use bgp_session::PassiveConnectionsAccepted;
use bgp_session::PrefixesAdvertised;
use bgp_session::PrefixesImported;
use bgp_session::TransitionToActive;
use bgp_session::TransitionToConnect;
use bgp_session::TransitionToEstablished;
use bgp_session::TransitionToIdle;
use bgp_session::TransitionToOpenConfirm;
use bgp_session::TransitionToOpenSent;
use bgp_session::TransitionToSessionSetup;
use bgp_session::UnexpectedKeepaliveMessages;
use bgp_session::UnexpectedOpenMessages;
use bgp_session::UnexpectedUpdateMessages;
use bgp_session::UpdateNexthopMissing;
use bgp_session::UpdateSendFailures;
use bgp_session::UpdatesReceived;
use bgp_session::UpdatesSent;

oximeter::use_timeseries!("static-routing-config.toml");
use static_routing_config::StaticNexthops;
use static_routing_config::StaticRoutes;
use static_routing_config::StaticRoutingConfig;

oximeter::use_timeseries!("mg-lower.toml");
use self::mg_lower::MgLower;
use self::mg_lower::RoutesBlockedByLinkState;

oximeter::use_timeseries!("switch-rib.toml");
use switch_rib::ActiveRoutes;
use switch_rib::SwitchRib;

#[derive(Clone)]
pub(crate) struct Stats {
    pub(crate) hostname: String,
    pub(crate) rack_id: Uuid,
    pub(crate) sled_id: Uuid,
    pub(crate) start_time: DateTime<Utc>,
    pub(crate) bfd: BfdContext,
    pub(crate) bgp: BgpContext,
    pub(crate) db: Db,
    pub(crate) mg_lower_stats: Arc<MgLowerStats>,
    log: Logger,
}

macro_rules! bgp_session_counter {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $start_time:expr,
        $local_asn:expr,
        $peer:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &BgpSession {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
                local_asn: $local_asn,
                peer: $peer,
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

macro_rules! bfd_session_counter {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $start_time:expr,
        $peer:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &BfdSession {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
                peer: $peer,
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

macro_rules! static_counter {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $start_time:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &StaticRoutingConfig {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
            },
            &$kind {
                datum: Cumulative::<u64>::with_start_time($start_time, $value),
            },
        )?
    };
}

macro_rules! mg_lower_quantity {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $start_time:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &MgLower {
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

macro_rules! rib_quantity {
    (
        $hostname:expr,
        $rack_id:expr,
        $sled_id:expr,
        $start_time:expr,
        $kind:tt,
        $value:expr
    ) => {
        Sample::new(
            &SwitchRib {
                hostname: $hostname,
                rack_id: $rack_id,
                sled_id: $sled_id,
            },
            &$kind { datum: $value },
        )?
    };
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stats")?;
        Ok(())
    }
}

impl Producer for Stats {
    fn produce(
        &mut self,
    ) -> Result<Box<dyn Iterator<Item = Sample>>, MetricsError> {
        let mut samples = Vec::new();

        match self.bgp_stats() {
            Ok(bgp) => samples.extend(bgp),
            Err(e) => {
                warn!(self.log, "failed to produce bgp samples: {e}");
            }
        }

        match self.bfd_stats() {
            Ok(bfd) => samples.extend(bfd),
            Err(e) => {
                warn!(self.log, "failed to produce bfd samples: {e}");
            }
        }

        match self.static_stats() {
            Ok(statics) => samples.extend(statics),
            Err(e) => {
                warn!(self.log, "failed to produce static route samples: {e}");
            }
        }

        match self.rib_stats() {
            Ok(rib) => samples.extend(rib),
            Err(e) => {
                warn!(self.log, "failed to produce rib samples: {e}");
            }
        }

        match self.mg_lower_stats() {
            Ok(mgl) => samples.extend(mgl),
            Err(e) => {
                warn!(self.log, "failed to produce mg lower samples: {e}");
            }
        }

        Ok(Box::new(samples.into_iter()))
    }
}

impl Stats {
    fn bgp_stats(&mut self) -> Result<Vec<Sample>, MetricsError> {
        let routers = lock!(self.bgp.router);
        let mut router_counters = BTreeMap::new();
        let mut session_count: usize = 0;
        for (asn, r) in &*routers {
            let mut session_counters = BTreeMap::new();
            let sessions = lock!(r.sessions);
            for (addr, session) in &*sessions {
                session_counters.insert(*addr, session.counters.clone());
                session_count += 1;
            }
            router_counters.insert(*asn, session_counters);
        }
        drop(routers);

        let mut samples = Vec::with_capacity(session_count * 29);

        for (asn, session_counters) in &router_counters {
            for (addr, counters) in session_counters {
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    KeepalivesSent,
                    counters.keepalives_sent
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    KeepalivesReceived,
                    counters.keepalives_received
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    OpensSent,
                    counters.opens_sent
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    OpensReceived,
                    counters.opens_received
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UpdatesSent,
                    counters.updates_sent
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UpdatesReceived,
                    counters.updates_received
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    PrefixesAdvertised,
                    counters.prefixes_advertised
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    PrefixesImported,
                    counters.prefixes_imported
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    IdleHoldTimerExpirations,
                    counters.idle_hold_timer_expirations
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    HoldTimerExpirations,
                    counters.hold_timer_expirations
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UpdateNexthopMissing,
                    counters.update_nexhop_missing
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    ActiveConnectionsAccepted,
                    counters.active_connections_accepted
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    PassiveConnectionsAccepted,
                    counters.passive_connections_accepted
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    ConnectionRetries,
                    counters.connection_retries
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    OpenHandleFailures,
                    counters.open_handle_failures
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToIdle,
                    counters.transitions_to_idle
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToConnect,
                    counters.transitions_to_connect
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToActive,
                    counters.transitions_to_active
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToOpenSent,
                    counters.transitions_to_open_sent
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToOpenConfirm,
                    counters.transitions_to_open_confirm
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToSessionSetup,
                    counters.transitions_to_session_setup
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    TransitionToEstablished,
                    counters.transitions_to_established
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UnexpectedUpdateMessages,
                    counters.unexpected_update_message
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UnexpectedKeepaliveMessages,
                    counters.unexpected_keepalive_message
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UnexpectedOpenMessages,
                    counters.unexpected_open_message
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    NotificationSendFailures,
                    counters.notification_send_failure
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    KeepaliveSendFailures,
                    counters.keepalive_send_failure
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    OpenSendFailures,
                    counters.open_send_failure
                ));
                samples.push(bgp_session_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    *asn,
                    *addr,
                    UpdateSendFailures,
                    counters.update_send_failure
                ));
            }
        }

        Ok(samples)
    }

    fn bfd_stats(&mut self) -> Result<Vec<Sample>, MetricsError> {
        let daemon = lock!(self.bfd.daemon);
        let mut counters = BTreeMap::new();
        for (addr, session) in &daemon.sessions {
            counters.insert(*addr, session.counters.clone());
        }
        drop(daemon);

        let mut samples = Vec::with_capacity(counters.len() * 8);

        for (addr, counters) in &counters {
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                ControlPacketsSent,
                counters.control_packets_sent
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                ControlPacketSendFailures,
                counters.control_packet_send_failures
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                ControlPacketsReceived,
                counters.control_packets_received
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                TransitionToInit,
                counters.transition_to_init
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                TransitionToDown,
                counters.transition_to_down
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                TransitionToUp,
                counters.transition_to_up
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                TimeoutExpired,
                counters.timeout_expired
            ));
            samples.push(bfd_session_counter!(
                self.hostname.clone().into(),
                self.rack_id,
                self.sled_id,
                self.start_time,
                *addr,
                MessageReceiveError,
                counters.message_receive_error
            ));
        }

        Ok(samples)
    }

    fn static_stats(&mut self) -> Result<Vec<Sample>, MetricsError> {
        let mut samples = Vec::new();

        match self.db.get_static4_count() {
            Ok(count) => {
                samples.push(static_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    StaticRoutes,
                    count as u64
                ));
            }
            Err(e) => {
                warn!(self.log, "stats: failed to get static4 count: {e}");
            }
        }
        match self.db.get_static_nexthop4_count() {
            Ok(count) => {
                samples.push(static_counter!(
                    self.hostname.clone().into(),
                    self.rack_id,
                    self.sled_id,
                    self.start_time,
                    StaticNexthops,
                    count as u64
                ));
            }
            Err(e) => {
                warn!(self.log, "stats: failed to get static4 count: {e}");
            }
        }

        Ok(samples)
    }

    fn rib_stats(&mut self) -> Result<Vec<Sample>, MetricsError> {
        let mut samples = Vec::new();

        let mut count = 0usize;
        for (_prefix, paths) in self.db.full_rib().iter() {
            count += paths.len();
        }
        samples.push(rib_quantity!(
            self.hostname.clone().into(),
            self.rack_id,
            self.sled_id,
            self.start_time,
            ActiveRoutes,
            count as u64
        ));

        Ok(samples)
    }

    fn mg_lower_stats(&mut self) -> Result<Vec<Sample>, MetricsError> {
        Ok(vec![mg_lower_quantity!(
            self.hostname.clone().into(),
            self.rack_id,
            self.sled_id,
            self.start_time,
            RoutesBlockedByLinkState,
            self.mg_lower_stats.routes_blocked_by_link_state
        )])
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn start_server(
    context: Arc<HandlerContext>,
    hostname: String,
    rack_id: Uuid,
    sled_id: Uuid,
    log: Logger,
) -> anyhow::Result<JoinHandle<()>> {
    let addr = local_underlay_address()?;
    let sa = SocketAddr::new(addr, context.oximeter_port);
    let log_config = LogConfig::Config(ConfigLogging::StderrTerminal {
        level: ConfigLoggingLevel::Debug,
    });
    let registry = ProducerRegistry::new();
    let stats_producer = Stats {
        hostname,
        rack_id,
        sled_id,
        start_time: chrono::offset::Utc::now(),
        bfd: context.bfd.clone(),
        bgp: context.bgp.clone(),
        db: context.db.clone(),
        mg_lower_stats: context.mg_lower_stats.clone(),
        log: log.clone(),
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
        request_body_max_bytes: 1024 * 1024 * 1024,
    };

    Ok(tokio::spawn(async move {
        run_oximeter(registry, config, log).await
    }))
}
