// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use iddqd::{BiHashItem, BiHashMap, bi_upcast};
use ndp::{Ipv6NetworkInterface, NewRouterDiscoveryError};
use slog::Logger;
use std::net::Ipv6Addr;
use std::num::NonZeroU32;
use std::sync::Arc;

enum RouterDiscoveryRuntime {
    #[cfg(test)]
    Manual {
        state: Arc<ndp::RouterDiscoveryState>,
    },
    Ndp {
        state: Arc<ndp::RouterDiscoveryState>,
        threads: ndp::RouterDiscoveryThreads,
    },
}

impl RouterDiscoveryRuntime {
    fn start(
        ifx: Ipv6NetworkInterface,
        tx_router_lifetime: u16,
        log: Logger,
    ) -> Result<Self, NewRouterDiscoveryError> {
        let state =
            Arc::new(ndp::RouterDiscoveryState::new(tx_router_lifetime));
        let threads =
            ndp::RouterDiscoveryThreads::start(ifx, Arc::clone(&state), log)?;

        Ok(Self::Ndp { state, threads })
    }

    #[cfg(test)]
    fn new_manual(tx_router_lifetime: u16) -> Self {
        Self::Manual {
            state: Arc::new(ndp::RouterDiscoveryState::new(tx_router_lifetime)),
        }
    }

    fn state(&self) -> &ndp::RouterDiscoveryState {
        match self {
            #[cfg(test)]
            Self::Manual { state } => state,
            Self::Ndp { state, .. } => state,
        }
    }

    fn discovered_neighbor(&self) -> Option<Ipv6Addr> {
        self.state().discovered_neighbor()
    }

    fn discovered_neighbor_info(&self) -> Option<ndp::RouterAdvertisementInfo> {
        self.state().discovered_neighbor_info()
    }

    fn tx_router_lifetime(&self) -> u16 {
        self.state().get_tx_router_lifetime()
    }

    fn set_tx_router_lifetime(&self, tx_router_lifetime: u16) {
        self.state().set_tx_router_lifetime(tx_router_lifetime);
    }

    fn get_runtime_state(&self) -> ndp::RouterDiscoveryRuntimeState {
        match self {
            #[cfg(test)]
            Self::Manual { .. } => ndp::RouterDiscoveryRuntimeState {
                tx_running: true,
                rx_running: true,
            },
            Self::Ndp { threads, .. } => threads.get_runtime_state(),
        }
    }

    #[cfg(test)]
    pub fn record_router_advertisement(
        &self,
        advertisement: ndp::Icmp6RouterAdvertisement,
        source: Ipv6Addr,
    ) {
        self.state().record_advertisement(advertisement, source);
    }

    #[cfg(test)]
    pub fn clear_discovered_neighbor(&self) {
        self.state().clear_neighbor();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NewUnnumberedInterfaceError {
    #[error("interface error: {0}")]
    Interface(#[from] UnnumberedInterfaceError),

    #[error("router discovery error: {0}")]
    RouterDiscovery(#[from] NewRouterDiscoveryError),
}

#[derive(Debug, thiserror::Error)]
pub enum UnnumberedInterfaceError {
    #[error("interface scope ID must be non-zero")]
    InvalidScopeId,

    #[error(
        "interface {interface} address {address} is not unicast link-local"
    )]
    NotLinkLocal {
        interface: String,
        address: Ipv6Addr,
    },
}

pub struct UnnumberedInterface {
    name: String,
    local_address: Ipv6Addr,
    scope_id: NonZeroU32,
    router_discovery: RouterDiscoveryRuntime,
}

impl UnnumberedInterface {
    pub fn new(
        ifx: Ipv6NetworkInterface,
        tx_router_lifetime: u16,
        log: Logger,
    ) -> Result<Self, NewUnnumberedInterfaceError> {
        let name = ifx.name.clone();
        let local_address = ifx.ip;
        let scope_id = ifx.scope_id;
        Self::validate_address(&name, local_address)?;

        let router_discovery =
            RouterDiscoveryRuntime::start(ifx, tx_router_lifetime, log)?;

        Ok(Self::from_validated_parts(
            name,
            local_address,
            scope_id,
            router_discovery,
        ))
    }

    #[cfg(test)]
    pub fn new_manual(
        name: impl Into<String>,
        local_address: Ipv6Addr,
        scope_id: u32,
        tx_router_lifetime: u16,
    ) -> Result<Self, UnnumberedInterfaceError> {
        let (name, scope_id) = Self::validate(name, local_address, scope_id)?;
        Ok(Self::from_validated_parts(
            name,
            local_address,
            scope_id,
            RouterDiscoveryRuntime::new_manual(tx_router_lifetime),
        ))
    }

    #[cfg(test)]
    fn validate(
        name: impl Into<String>,
        local_address: Ipv6Addr,
        scope_id: u32,
    ) -> Result<(String, NonZeroU32), UnnumberedInterfaceError> {
        let name = name.into();
        let scope_id = NonZeroU32::new(scope_id)
            .ok_or(UnnumberedInterfaceError::InvalidScopeId)?;
        Self::validate_address(&name, local_address)?;
        Ok((name, scope_id))
    }

    fn validate_address(
        name: &str,
        local_address: Ipv6Addr,
    ) -> Result<(), UnnumberedInterfaceError> {
        if !local_address.is_unicast_link_local() {
            return Err(UnnumberedInterfaceError::NotLinkLocal {
                interface: name.to_string(),
                address: local_address,
            });
        }
        Ok(())
    }

    fn from_validated_parts(
        name: String,
        local_address: Ipv6Addr,
        scope_id: NonZeroU32,
        router_discovery: RouterDiscoveryRuntime,
    ) -> Self {
        Self {
            name,
            local_address,
            scope_id,
            router_discovery,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn local_address(&self) -> Ipv6Addr {
        self.local_address
    }

    pub fn scope_id(&self) -> NonZeroU32 {
        self.scope_id
    }

    pub fn discovered_neighbor(&self) -> Option<Ipv6Addr> {
        self.router_discovery.discovered_neighbor()
    }

    pub fn discovered_neighbor_info(
        &self,
    ) -> Option<ndp::RouterAdvertisementInfo> {
        self.router_discovery.discovered_neighbor_info()
    }

    pub fn tx_router_lifetime(&self) -> u16 {
        self.router_discovery.tx_router_lifetime()
    }

    pub fn set_tx_router_lifetime(&self, tx_router_lifetime: u16) {
        self.router_discovery
            .set_tx_router_lifetime(tx_router_lifetime);
    }

    pub fn get_runtime_state(&self) -> ndp::RouterDiscoveryRuntimeState {
        self.router_discovery.get_runtime_state()
    }

    #[cfg(test)]
    pub fn record_router_advertisement(
        &self,
        advertisement: ndp::Icmp6RouterAdvertisement,
        source: Ipv6Addr,
    ) {
        self.router_discovery
            .record_router_advertisement(advertisement, source);
    }

    #[cfg(test)]
    pub fn clear_discovered_neighbor(&self) {
        self.router_discovery.clear_discovered_neighbor();
    }
}

impl BiHashItem for UnnumberedInterface {
    type K1<'a> = NonZeroU32;
    type K2<'a> = &'a str;

    fn key1(&self) -> Self::K1<'_> {
        self.scope_id
    }

    fn key2(&self) -> Self::K2<'_> {
        &self.name
    }

    bi_upcast!();
}

/// Active unnumbered interface map indexed by scope ID and interface name.
///
/// Wraps a `BiHashMap` to provide domain-specific accessors for the BGP
/// dispatcher's scope ID lookups and interface lifecycle paths that need
/// lookup/removal by interface name.
pub struct InterfaceMap(BiHashMap<UnnumberedInterface>);

impl Default for InterfaceMap {
    fn default() -> Self {
        Self(BiHashMap::new())
    }
}

impl InterfaceMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an active interface, overwriting any existing entries that
    /// collide on scope ID or interface name. Returns the displaced active
    /// interfaces, if any.
    pub fn insert_overwrite(
        &mut self,
        interface: UnnumberedInterface,
    ) -> Vec<UnnumberedInterface> {
        self.0.insert_overwrite(interface)
    }

    pub fn remove_by_name(
        &mut self,
        interface: &str,
    ) -> Option<UnnumberedInterface> {
        self.0.remove2(interface)
    }

    pub fn get_by_scope_id(
        &self,
        scope_id: NonZeroU32,
    ) -> Option<&UnnumberedInterface> {
        self.0.get1(&scope_id)
    }

    pub fn get_by_name(&self, interface: &str) -> Option<&UnnumberedInterface> {
        self.0.get2(interface)
    }

    pub fn contains_scope_id(&self, scope_id: NonZeroU32) -> bool {
        self.0.contains_key1(&scope_id)
    }

    pub fn contains_name(&self, interface: &str) -> bool {
        self.0.contains_key2(interface)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &UnnumberedInterface> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    #[derive(Clone, Debug)]
    struct InterfaceSpec {
        name: String,
        scope_id: u32,
        address_suffix: u16,
    }

    #[derive(Clone, Debug)]
    enum InterfaceMapOp {
        Insert(InterfaceSpec),
        Remove { name: String },
    }

    fn link_local(n: u16) -> Ipv6Addr {
        format!("fe80::{n}").parse().unwrap()
    }

    fn global(n: u16) -> Ipv6Addr {
        format!("2001:db8::{n}").parse().unwrap()
    }

    fn manual_interface(
        name: &str,
        addr: Ipv6Addr,
        scope_id: u32,
    ) -> UnnumberedInterface {
        UnnumberedInterface::new_manual(name, addr, scope_id, 30).unwrap()
    }

    fn interface_name() -> impl Strategy<Value = String> {
        (0u8..8).prop_map(|n| format!("eth{n}"))
    }

    fn interface_spec() -> impl Strategy<Value = InterfaceSpec> {
        (interface_name(), 1u32..=8, 1u16..=1024).prop_map(
            |(name, scope_id, address_suffix)| InterfaceSpec {
                name,
                scope_id,
                address_suffix,
            },
        )
    }

    fn interface_map_op() -> impl Strategy<Value = InterfaceMapOp> {
        prop_oneof![
            interface_spec().prop_map(InterfaceMapOp::Insert),
            interface_name().prop_map(|name| InterfaceMapOp::Remove { name }),
        ]
    }

    fn interface_pairs(
        interfaces: impl IntoIterator<Item = UnnumberedInterface>,
    ) -> Vec<(String, u32)> {
        let mut pairs = interfaces
            .into_iter()
            .map(|interface| {
                (interface.name().to_owned(), interface.scope_id().get())
            })
            .collect::<Vec<_>>();
        pairs.sort();
        pairs
    }

    fn expected_pairs(
        expected_by_name: &BTreeMap<String, u32>,
    ) -> Vec<(String, u32)> {
        expected_by_name
            .iter()
            .map(|(name, scope_id)| (name.clone(), *scope_id))
            .collect()
    }

    fn assert_interface_map_matches_model(
        map: &InterfaceMap,
        expected_by_name: &BTreeMap<String, u32>,
        expected_by_scope: &BTreeMap<u32, String>,
    ) {
        assert_eq!(map.is_empty(), expected_by_name.is_empty());
        assert_eq!(expected_by_name.len(), expected_by_scope.len());

        let actual_pairs = map
            .iter()
            .map(|interface| {
                (interface.name().to_owned(), interface.scope_id().get())
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(&actual_pairs, expected_by_name);

        for (name, scope_id) in expected_by_name {
            let scope_id = NonZeroU32::new(*scope_id).unwrap();
            let by_name = map.get_by_name(name).unwrap();
            let by_scope = map.get_by_scope_id(scope_id).unwrap();

            assert!(map.contains_name(name));
            assert!(map.contains_scope_id(scope_id));
            assert_eq!(by_name.name(), name);
            assert_eq!(by_name.scope_id(), scope_id);
            assert_eq!(by_scope.name(), name);
            assert_eq!(by_scope.scope_id(), scope_id);
        }

        for (scope_id, name) in expected_by_scope {
            assert_eq!(expected_by_name.get(name), Some(scope_id));
        }
    }

    #[test]
    fn new_manual_rejects_zero_scope_id() {
        let result =
            UnnumberedInterface::new_manual("eth0", link_local(1), 0, 30);

        assert!(matches!(
            result,
            Err(UnnumberedInterfaceError::InvalidScopeId)
        ));
    }

    #[test]
    fn new_manual_rejects_non_link_local_address() {
        let result = UnnumberedInterface::new_manual("eth0", global(1), 1, 30);

        assert!(matches!(
            result,
            Err(UnnumberedInterfaceError::NotLinkLocal { .. })
        ));
    }

    #[test]
    fn manual_interface_records_and_clears_discovered_neighbor() {
        let interface = manual_interface("eth0", link_local(1), 1);
        let source = link_local(2);
        let advertisement = ndp::Icmp6RouterAdvertisement {
            lifetime: 42,
            reachable_time: 5000,
            retrans_timer: 1000,
            ..Default::default()
        };

        assert_eq!(interface.discovered_neighbor(), None);

        interface.record_router_advertisement(advertisement, source);

        assert_eq!(interface.discovered_neighbor(), Some(source));
        let info = interface.discovered_neighbor_info().unwrap();
        assert_eq!(info.address, source);
        assert_eq!(info.router_lifetime, 42);
        assert_eq!(info.reachable_time, 5000);
        assert_eq!(info.retrans_timer, 1000);
        assert!(!info.expired);

        interface.clear_discovered_neighbor();
        assert_eq!(interface.discovered_neighbor(), None);
    }

    #[test]
    fn manual_interface_reports_available_runtime_state() {
        let interface = manual_interface("eth0", link_local(1), 1);

        let state = interface.get_runtime_state();

        assert!(state.tx_running);
        assert!(state.rx_running);
    }

    #[test]
    fn interface_map_indexes_by_name_and_scope_id() {
        let mut map = InterfaceMap::new();
        let interface = manual_interface("eth0", link_local(1), 1);

        assert!(map.insert_overwrite(interface).is_empty());

        assert_eq!(map.get_by_name("eth0").unwrap().scope_id().get(), 1);
        assert_eq!(
            map.get_by_scope_id(NonZeroU32::new(1).unwrap())
                .unwrap()
                .name(),
            "eth0"
        );
    }

    #[test]
    fn interface_map_overwrites_name_and_scope_id_collisions() {
        let mut map = InterfaceMap::new();
        assert!(
            map.insert_overwrite(manual_interface("eth0", link_local(1), 1))
                .is_empty()
        );
        assert!(
            map.insert_overwrite(manual_interface("eth1", link_local(2), 2))
                .is_empty()
        );

        let displaced =
            map.insert_overwrite(manual_interface("eth0", link_local(3), 2));

        assert_eq!(displaced.len(), 2);
        assert_eq!(map.iter().count(), 1);
        assert_eq!(map.get_by_name("eth0").unwrap().scope_id().get(), 2);
        assert!(map.get_by_name("eth1").is_none());
        assert!(map.get_by_scope_id(NonZeroU32::new(1).unwrap()).is_none());
    }

    proptest! {
        #[test]
        fn proptest_interface_map_keeps_name_and_scope_indexes_consistent(
            ops in prop::collection::vec(interface_map_op(), 0..64),
        ) {
            let mut map = InterfaceMap::new();
            let mut expected_by_name = BTreeMap::new();
            let mut expected_by_scope = BTreeMap::new();

            for op in ops {
                match op {
                    InterfaceMapOp::Insert(spec) => {
                        let mut expected_displaced = Vec::new();

                        if let Some(old_scope_id) =
                            expected_by_name.remove(&spec.name)
                        {
                            expected_by_scope.remove(&old_scope_id);
                            expected_displaced
                                .push((spec.name.clone(), old_scope_id));
                        }

                        if let Some(old_name) =
                            expected_by_scope.remove(&spec.scope_id)
                        {
                            let old_scope_id = expected_by_name
                                .remove(&old_name)
                                .unwrap();
                            expected_displaced.push((old_name, old_scope_id));
                        }

                        expected_displaced.sort();
                        expected_by_name
                            .insert(spec.name.clone(), spec.scope_id);
                        expected_by_scope
                            .insert(spec.scope_id, spec.name.clone());

                        let displaced = map.insert_overwrite(manual_interface(
                            &spec.name,
                            link_local(spec.address_suffix),
                            spec.scope_id,
                        ));

                        prop_assert_eq!(
                            interface_pairs(displaced),
                            expected_displaced,
                        );
                    }
                    InterfaceMapOp::Remove { name } => {
                        let removed = map.remove_by_name(&name);
                        let expected_removed = expected_by_name
                            .remove(&name)
                            .map(|scope_id| {
                                expected_by_scope.remove(&scope_id);
                                vec![(name, scope_id)]
                            })
                            .unwrap_or_default();

                        let removed = removed.into_iter().collect::<Vec<_>>();
                        prop_assert_eq!(
                            interface_pairs(removed),
                            expected_removed,
                        );
                    }
                }

                assert_interface_map_matches_model(
                    &map,
                    &expected_by_name,
                    &expected_by_scope,
                );
                prop_assert_eq!(
                    map.iter()
                        .map(|interface| {
                            (
                                interface.name().to_owned(),
                                interface.scope_id().get(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>()
                        .into_iter()
                        .collect::<Vec<_>>(),
                    expected_pairs(&expected_by_name),
                );
            }
        }
    }
}
