//! BIRD's configuration and CLI text formats, independent of the Falcon runtime.

use std::net::{IpAddr, Ipv6Addr};

pub const MD5_KEY: &str = "falcon-bgp-md5-test-key";
pub const ASN: u32 = 48;

pub struct BgpLink {
    pub interface: String,
    pub local: Ipv6Addr,
    pub remote: Ipv6Addr,
}

pub fn bgp_config(links: &[BgpLink]) -> String {
    let mut config = format!(
        r#"router id 1.2.3.3;
log stderr all;
protocol device {{}}
protocol static origins4 {{ ipv4; route 1.2.3.0/24 blackhole; }}
protocol static origins6 {{ ipv6; route fd99::/64 blackhole; }}
template bgp dut_unnumbered {{
    local as {ASN};
    neighbor as 33;
    direct;
    authentication md5;
    password "{MD5_KEY}";
    hold time 6;
    keepalive time 2;
    connect delay time 1;
    connect retry time 1;
    error wait time 1, 5;
    graceful restart off;
    ipv4 {{
        import all;
        export filter {{
            if (source = RTS_STATIC) && (net = 1.2.3.0/24) then {{
                bgp_origin = ORIGIN_IGP; accept;
            }}
            reject;
        }};
        extended next hop on;
    }};
    ipv6 {{
        import all;
        export filter {{
            if (source = RTS_STATIC) && (net = fd99::/64) then {{
                bgp_origin = ORIGIN_IGP; accept;
            }}
            reject;
        }};
    }};
}}
protocol radv discovery {{
"#
    );
    for link in links {
        config.push_str(&format!(r#"    interface "{}" {{ min ra interval 3; max ra interval 4; default lifetime 0; }};
"#, link.interface));
    }
    config.push_str("}\n");
    for (index, link) in links.iter().enumerate() {
        config.push_str(&format!(
            r#"protocol bgp dut{index} from dut_unnumbered {{
    interface "{}";
    local {};
    neighbor {};
}}
"#,
            link.interface, link.local, link.remote
        ));
    }
    config
}

pub fn bfd_config(interface: &str) -> String {
    format!(
        r#"router id 1.2.3.3;
log stderr all;
protocol device {{}}
protocol bfd peers {{
    interface "{interface}" {{ interval 1 s; multiplier 3; }};
    neighbor 10.0.4.1 dev "{interface}" local 10.0.4.2;
    neighbor fd00:5::1 dev "{interface}" local fd00:5::2;
}}
"#
    )
}

pub fn protocol_established(output: &str, name: &str) -> bool {
    output.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() >= 6
            && fields[0] == name
            && fields[1] == "BGP"
            && fields[3] == "up"
            && fields.last() == Some(&"Established")
    })
}

pub fn route_imported(output: &str, name: &str, prefix: &str) -> bool {
    output.lines().any(|line| {
        line.split_whitespace().next() == Some(prefix)
            && line.contains(&format!("[{name} "))
    }) && output.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("Type:") && fields.next() == Some("BGP")
    })
}

pub fn bfd_peers_up(output: &str, wanted: &[IpAddr]) -> bool {
    wanted.iter().all(|peer| {
        output.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() >= 3
                && fields[0].parse::<IpAddr>().ok() == Some(*peer)
                && fields[2] == "Up"
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn generated_bgp_is_scoped_authenticated_and_export_filtered() {
        for count in [1, 3] {
            let links: Vec<_> = (0..count)
                .map(|i| BgpLink {
                    interface: format!("enp0s{}", 8 + i),
                    local: format!("fe80::{}", i + 1).parse().unwrap(),
                    remote: format!("fe80::{}", i + 10).parse().unwrap(),
                })
                .collect();
            let config = bgp_config(&links);
            assert_eq!(config.matches("from dut_unnumbered").count(), count);
            assert_eq!(config.matches("default lifetime 0").count(), count);
            assert!(config.contains("authentication md5;"));
            assert!(config.contains(&format!("password \"{MD5_KEY}\";")));
            assert!(config.contains("extended next hop on;"));
            assert_eq!(config.matches("source = RTS_STATIC").count(), 2);
            for (index, link) in links.iter().enumerate() {
                assert!(config.contains(&format!("protocol bgp dut{index}")));
                assert!(config.contains(&format!("neighbor {};", link.remote)));
            }
        }
    }

    #[test]
    fn cli_checks_reject_missing_down_and_wrong_source() {
        assert!(protocol_established(
            "dut0 BGP --- up 12:00:00 Established",
            "dut0"
        ));
        assert!(!protocol_established(
            "dut0 BGP --- start 12:00:00 Active",
            "dut0"
        ));
        assert!(!protocol_established("Unable to connect to server", "dut0"));
        let route =
            "4.5.6.0/24 unicast [dut0 12:00:00] * (100)\n Type: BGP univ";
        assert!(route_imported(route, "dut0", "4.5.6.0/24"));
        assert!(!route_imported(route, "dut1", "4.5.6.0/24"));
        assert!(!route_imported(route, "dut0", "4.5.0.0/16"));
        assert!(!route_imported(
            &route.replace("BGP", "static"),
            "dut0",
            "4.5.6.0/24"
        ));
        let wanted =
            ["10.0.4.1".parse().unwrap(), "fd00:5::1".parse().unwrap()];
        let bfd = "IP address Interface State Since Interval Timeout\n10.0.4.1 enp0s8 Up 12:00:00 1.000 3.000\nfd00:5::1 enp0s8 Up 12:00:00 1.000 3.000";
        assert!(bfd_peers_up(bfd, &wanted));
        assert!(!bfd_peers_up(
            &bfd.replace("fd00:5::1 enp0s8 Up", "fd00:5::1 enp0s8 Down"),
            &wanted
        ));
        assert!(!bfd_peers_up("", &wanted));
    }

    /// Set BIRD_CONFIG_DIR to retain the exact generated fixtures for bird -p
    /// validation on a Linux host; no daemon is started by this test.
    #[test]
    fn export_parser_fixtures() {
        let Ok(dir) = std::env::var("BIRD_CONFIG_DIR") else {
            return;
        };
        fs::create_dir_all(&dir).unwrap();
        for count in [1, 3] {
            let links: Vec<_> = (0..count)
                .map(|i| BgpLink {
                    interface: format!("eth{i}"),
                    local: format!("fe80::{}", i + 1).parse().unwrap(),
                    remote: format!("fe80::{}", i + 10).parse().unwrap(),
                })
                .collect();
            fs::write(format!("{dir}/bgp-{count}.conf"), bgp_config(&links))
                .unwrap();
        }
        fs::write(format!("{dir}/bfd.conf"), bfd_config("eth0")).unwrap();
    }
}
