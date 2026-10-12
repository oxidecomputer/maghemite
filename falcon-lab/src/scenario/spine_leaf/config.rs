//! Address plan and transit-only spine configurations.

use super::SpineLeafScenario;
use crate::bird::BgpLink;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) const LEAF_ASNS: [u32; 2] = [65001, 65002];
pub(super) const SPINES: [(&str, u32); 4] = [
    ("frr", 65101),
    ("eos", 65102),
    ("junos", 65103),
    ("bird", 65104),
];
pub(super) const ORIGINS4: [&str; 2] = ["198.51.100.0/24", "203.0.113.0/24"];
pub(super) const ORIGINS6: [&str; 2] = ["2001:db8:1::/64", "2001:db8:2::/64"];

// Eight distinct subnets; host 1 is the leaf, host 2 the spine.
pub(super) fn addresses(
    leaf: usize,
    spine: usize,
    host: u8,
) -> (Ipv4Addr, Ipv6Addr) {
    let subnet = (leaf * 4 + spine) as u8;
    (
        Ipv4Addr::new(10, 20, subnet, host),
        Ipv6Addr::new(
            0xfd20,
            u16::from(subnet) + 1,
            0,
            0,
            0,
            0,
            0,
            u16::from(host),
        ),
    )
}

pub(super) fn frr(scenario: SpineLeafScenario) -> String {
    let mut config =
        String::from("configure\nip forwarding\nipv6 forwarding\n");
    for leaf in 0..2 {
        let interface = format!("enp0s{}", 8 + leaf);
        config.push_str(&format!("interface {interface}\n no shutdown\n"));
        if scenario.numbered() {
            let (v4, v6) = addresses(leaf, 0, 2);
            config.push_str(&format!(
                " ip address {v4}/24\n ipv6 address {v6}/64\n"
            ));
        } else {
            config
                .push_str(" ipv6 nd ra-interval 4\n no ipv6 nd suppress-ra\n");
        }
        config.push_str("exit\n");
    }
    config.push_str(&format!(
        "router bgp {}
          bgp router-id 10.255.0.101
          no bgp default ipv4-unicast
          no bgp ebgp-requires-policy
          timers bgp 2 6
        ",
        SPINES[0].1
    ));
    for (leaf, asn) in LEAF_ASNS.iter().enumerate() {
        if scenario.numbered() {
            let (v4, v6) = addresses(leaf, 0, 1);
            for peer in [v4.to_string(), v6.to_string()] {
                config.push_str(&format!(" neighbor {peer} remote-as {asn}\n"));
            }
            for (af, peer) in
                [("ipv4", v4.to_string()), ("ipv6", v6.to_string())]
            {
                config.push_str(&format!(
                    "address-family {af} unicast
                      neighbor {peer} activate
                      neighbor {peer} next-hop-self
                    exit-address-family
                    "
                ));
            }
        } else {
            let peer = format!("enp0s{}", 8 + leaf);
            config.push_str(&format!(
                "neighbor {peer} interface remote-as {asn}
                 neighbor {peer} capability extended-nexthop
                "
            ));
            for af in ["ipv4", "ipv6"] {
                config.push_str(&format!(
                    "address-family {af} unicast
                      neighbor {peer} activate
                      neighbor {peer} next-hop-self
                    exit-address-family
                    "
                ));
            }
        }
    }
    config.push_str("end\n");
    config
}

pub(super) fn eos(scenario: SpineLeafScenario) -> String {
    let mut config = String::from(
        "enable\nconfigure\nip routing\nipv6 unicast-routing\nip routing ipv6 interfaces\n",
    );
    for leaf in 0..2 {
        config.push_str(&format!(
            "interface Ethernet{}
              no switchport
              no shutdown
              ipv6 enable
            ",
            leaf + 1
        ));
        if scenario.numbered() {
            let (v4, v6) = addresses(leaf, 1, 2);
            config.push_str(&format!(
                " ip address {v4}/24\n ipv6 address {v6}/64\n"
            ));
        }
        config.push_str("exit\n");
    }
    config.push_str(&format!(
        "router bgp {}
          router-id 10.255.0.102
          no bgp default ipv4-unicast
          timers bgp 2 6
        ",
        SPINES[1].1
    ));
    for (leaf, asn) in LEAF_ASNS.iter().enumerate() {
        if scenario.numbered() {
            let (v4, v6) = addresses(leaf, 1, 1);
            for peer in [v4.to_string(), v6.to_string()] {
                config.push_str(&format!(
                    "neighbor {peer} remote-as {asn}
                     neighbor {peer} next-hop-self
                    "
                ));
            }
            for (af, peer) in
                [("ipv4", v4.to_string()), ("ipv6", v6.to_string())]
            {
                config.push_str(&format!(
                    " address-family {af}\n  neighbor {peer} activate\n exit\n"
                ));
            }
        } else {
            let group = format!("leaf{}", leaf + 1);
            config.push_str(&format!(
                "neighbor {group} peer group
                 neighbor {group} remote-as {asn}
                 neighbor interface Et{} peer-group {group}
                ",
                leaf + 1
            ));
            for af in ["ipv4", "ipv6"] {
                config.push_str(&format!(
                    "address-family {af}
                      neighbor {group} activate
                      neighbor {group} next-hop address-family ipv6 originate
                    exit
                    "
                ));
            }
        }
    }
    config.push_str("end\n");
    config
}

pub(super) fn junos(scenario: SpineLeafScenario) -> String {
    let mut config = format!(
        "set routing-options router-id 10.255.0.103
         set routing-options autonomous-system {}
         set policy-options policy-statement transit term bgp from protocol bgp
         set policy-options policy-statement transit term bgp then next-hop self
         set policy-options policy-statement transit term bgp then accept
         set policy-options policy-statement transit then reject
        ",
        SPINES[2].1
    );
    for (leaf, asn) in LEAF_ASNS.iter().enumerate() {
        let interface = format!("eth{}", leaf + 1);
        let group = format!("leaf{}", leaf + 1);
        if scenario.numbered() {
            let (local4, local6) = addresses(leaf, 2, 2);
            let (remote4, remote6) = addresses(leaf, 2, 1);
            config.push_str(&format!(
                "set interfaces {interface} unit 0 family inet address {local4}/24
                 set interfaces {interface} unit 0 family inet6 address {local6}/64
                "));
            for (suffix, family, local, remote) in [
                ("v4", "inet", local4.to_string(), remote4.to_string()),
                ("v6", "inet6", local6.to_string(), remote6.to_string()),
            ] {
                let group = format!("{group}-{suffix}");
                config.push_str(&format!(
                    "set protocols bgp group {group} type external
                     set protocols bgp group {group} peer-as {asn}
                     set protocols bgp group {group} local-address {local}
                     set protocols bgp group {group} family {family} unicast
                     set protocols bgp group {group} export transit
                     set protocols bgp group {group} neighbor {remote}
                    "
                ));
            }
        } else {
            config.push_str(&format!(
                "set interfaces {interface} unit 0 family inet
                 set interfaces {interface} unit 0 family inet6
                 set protocols router-advertisement interface {interface}
                 set protocols bgp group {group} type external
                 set protocols bgp group {group} peer-as {asn}
                 set protocols bgp group {group} family inet unicast extended-nexthop
                 set protocols bgp group {group} family inet6 unicast
                 set protocols bgp group {group} export transit
                 set protocols bgp group {group} dynamic-neighbor {group} peer-auto-discovery family inet6 ipv6-nd
                 set protocols bgp group {group} dynamic-neighbor {group} peer-auto-discovery interface {interface}
                "));
        }
    }
    config
}

pub(super) fn bird(scenario: SpineLeafScenario, links: &[BgpLink]) -> String {
    let mut config = String::from(
        "router id 10.255.0.104;\nlog stderr all;\nprotocol device {}\n",
    );
    for (leaf, link) in links.iter().enumerate() {
        let asn = LEAF_ASNS[leaf];
        let local_asn = SPINES[3].1;
        if scenario.numbered() {
            let (local4, local6) = addresses(leaf, 3, 2);
            let (remote4, remote6) = addresses(leaf, 3, 1);
            for (af, local, remote) in [
                ("ipv4", local4.to_string(), remote4.to_string()),
                ("ipv6", local6.to_string(), remote6.to_string()),
            ] {
                config.push_str(&format!(
                    "protocol bgp leaf{leaf}_{af} {{
                        local {local} as {local_asn};
                        neighbor {remote} as {asn};
                        direct;
                        {af} {{ import all; export all; next hop self; }};
                    }}
                    "
                ));
            }
        } else {
            config.push_str(&format!(
                "protocol bgp leaf{leaf} {{
                    interface \"{}\";
                    local {} as {local_asn};
                    neighbor {} as {asn};
                    direct;
                    ipv4 {{ import all; export all; next hop self; extended next hop on; }};
                    ipv6 {{ import all; export all; next hop self; }};
                }}
                ", link.interface, link.local, link.remote));
        }
    }
    if !scenario.numbered() {
        config.push_str("protocol radv discovery {\n");
        for link in links {
            config.push_str(&format!(" interface \"{}\" {{ min ra interval 3; max ra interval 4; default lifetime 0; }};\n", link.interface));
        }
        config.push_str("}\n");
    }
    config
}
