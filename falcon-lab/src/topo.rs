//! Testing topologies

use anyhow::Result;
use libfalcon::{Runner, node, unit::gb};

use crate::{
    ddm::DdmNode, eos::EosNode, frr::FrrNode, juniper::JuniperNode,
    mgd::MgdNode,
};

pub struct DdmTrio {
    pub d: Runner,
    pub hub: DdmNode,
    pub peer1: DdmNode,
    pub peer2: DdmNode,
}

pub struct MgdDuo {
    pub d: Runner,
    pub ox1: MgdNode,
    pub ox2: MgdNode,
}

pub struct Quartet {
    pub d: Runner,
    pub ox: MgdNode,
    pub cr1: FrrNode,
    pub cr2: EosNode,
    pub cr3: JuniperNode,
}

/// Three DDM routers in a star. The hub's first two interfaces connect to one
/// leaf each, allowing their FSM lifecycles to be controlled independently.
pub fn ddm_trio(name: &str) -> Result<DdmTrio> {
    let mut d = Runner::new(name);

    node!(d, hub, "helios-3.0", 4, gb(4));
    node!(d, peer1, "helios-3.0", 4, gb(4));
    node!(d, peer2, "helios-3.0", 4, gb(4));

    d.link(hub, peer1);
    d.link(hub, peer2);

    d.default_ext_link(hub)?;
    d.default_ext_link(peer1)?;
    d.default_ext_link(peer2)?;

    d.mount("cargo-bay", "/opt/cargo-bay", hub)?;
    d.mount("cargo-bay", "/opt/cargo-bay", peer1)?;
    d.mount("cargo-bay", "/opt/cargo-bay", peer2)?;

    Ok(DdmTrio {
        d,
        hub: DdmNode(hub),
        peer1: DdmNode(peer1),
        peer2: DdmNode(peer2),
    })
}

pub fn mgd_duo(name: &str) -> Result<MgdDuo> {
    let mut d = Runner::new(name);

    node!(d, ox1, "helios-3.0", 4, gb(4));
    node!(d, ox2, "helios-3.0", 4, gb(4));

    d.link(ox1, ox2);

    d.default_ext_link(ox1)?;
    d.default_ext_link(ox2)?;

    d.mount("cargo-bay", "/opt/cargo-bay", ox1)?;
    d.mount("cargo-bay", "/opt/cargo-bay", ox2)?;

    Ok(MgdDuo {
        d,
        ox1: MgdNode(ox1),
        ox2: MgdNode(ox2),
    })
}

pub fn quartet(name: &str) -> Result<Quartet> {
    let mut d = Runner::new(name);

    // nodes
    node!(d, ox, "helios-3.0", 4, gb(4));
    node!(d, cr1, "debian-13.2", 4, gb(4));
    node!(d, cr2, "eos-4.35", 4, gb(4));
    node!(d, cr3, "junos-23.2", 4, gb(4));

    // links
    let mut mac_counter = 0;
    let mut new_mac = || {
        mac_counter += 1;
        format!("a8:40:25:00:00:{mac_counter:02}")
    };

    d.softnpu_link(ox, cr1, Some(new_mac()), None);
    d.softnpu_link(ox, cr2, Some(new_mac()), None);
    d.softnpu_link(ox, cr3, Some(new_mac()), None);

    d.default_ext_link(ox)?;
    d.default_ext_link(cr1)?;
    d.default_ext_link(cr2)?;
    d.default_ext_link(cr3)?;

    d.mount("cargo-bay", "/opt/cargo-bay", ox)?;
    d.mount_linux("cargo-bay", "/opt/cargo-bay", cr1)?;
    d.mount("cargo-bay", "/opt/cargo-bay", cr2)?;
    d.mount_linux("cargo-bay", "/opt/cargo-bay", cr3)?;
    // The Junos image mounts cargo-bay and applies staged configuration from
    // guest-side systemd services. Keep the 9p device in the spec, but avoid
    // Falcon's serial-driven setup/mount path for this node.
    d.do_setup(cr3, false);

    Ok(Quartet {
        d,
        ox: MgdNode(ox),
        cr1: FrrNode(cr1),
        cr2: EosNode(cr2),
        cr3: JuniperNode(cr3),
    })
}
