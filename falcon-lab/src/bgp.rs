//! BGP utilities

use mg_admin_client::types::{Neighbor, UnnumberedNeighbor};
use mg_api_types::bgp::config::{Ipv4UnicastConfig, Ipv6UnicastConfig};
use mg_api_types::bgp::policy::{ImportExportPolicy4, ImportExportPolicy6};
use std::net::{IpAddr, SocketAddr};

/// A numbered peer carrying only the unicast AF matching its transport.
pub fn basic_numbered_neighbor(
    name: &str,
    group: &str,
    addr: IpAddr,
    local_asn: u32,
    remote_asn: u32,
) -> Neighbor {
    Neighbor {
        asn: local_asn,
        name: name.to_owned(),
        group: group.to_owned(),
        host: SocketAddr::new(addr, 179),
        remote_asn: Some(remote_asn),
        communities: Vec::new(),
        connect_retry: 5,
        delay_open: 0,
        enforce_first_as: true,
        hold_time: 6,
        idle_hold_time: 0,
        keepalive: 2,
        local_pref: None,
        md5_auth_key: None,
        min_ttl: None,
        multi_exit_discriminator: None,
        passive: false,
        resolution: 100,
        vlan_id: None,
        ipv4_unicast: addr.is_ipv4().then_some(Ipv4UnicastConfig {
            import_policy: ImportExportPolicy4::NoFiltering,
            export_policy: ImportExportPolicy4::NoFiltering,
            nexthop: None,
        }),
        ipv6_unicast: addr.is_ipv6().then_some(Ipv6UnicastConfig {
            import_policy: ImportExportPolicy6::NoFiltering,
            export_policy: ImportExportPolicy6::NoFiltering,
            nexthop: None,
        }),
        connect_retry_jitter: None,
        deterministic_collision_resolution: false,
        idle_hold_jitter: None,
        src_addr: None,
        src_port: None,
    }
}

pub fn basic_unnumbered_neighbor(
    name: &str,
    group: &str,
    interface: &str,
    local_asn: u32,
    act_as_a_default_ipv6_router: u16,
) -> UnnumberedNeighbor {
    UnnumberedNeighbor {
        asn: local_asn,
        act_as_a_default_ipv6_router,
        communities: Vec::default(),
        connect_retry: 5,
        delay_open: 0,
        enforce_first_as: false,
        group: group.to_owned(),
        hold_time: 6,
        idle_hold_time: 0,
        interface: interface.to_string(),
        keepalive: 2,
        local_pref: None,
        md5_auth_key: None,
        min_ttl: None,
        multi_exit_discriminator: None,
        name: name.to_string(),
        passive: false,
        remote_asn: None,
        resolution: 100,
        vlan_id: None,
        ipv4_unicast: Some(Ipv4UnicastConfig {
            import_policy: ImportExportPolicy4::NoFiltering,
            export_policy: ImportExportPolicy4::NoFiltering,
            nexthop: None,
        }),
        ipv6_unicast: Some(Ipv6UnicastConfig {
            import_policy: ImportExportPolicy6::NoFiltering,
            export_policy: ImportExportPolicy6::NoFiltering,
            nexthop: None,
        }),
        connect_retry_jitter: None,
        deterministic_collision_resolution: false,
        idle_hold_jitter: None,
        src_addr: None,
        src_port: None,
    }
}
