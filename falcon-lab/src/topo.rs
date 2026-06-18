//! Testing topologies

use anyhow::Result;
use libfalcon::{Runner, node, unit::gb};

use crate::{eos::EosNode, frr::FrrNode, mgd::MgdNode};

pub struct MgdDuo {
    pub d: Runner,
    pub ox1: MgdNode,
    pub ox2: MgdNode,
}

pub struct Trio {
    pub d: Runner,
    pub ox: MgdNode,
    pub cr1: FrrNode,
    pub cr2: EosNode,
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

pub fn trio(name: &str) -> Result<Trio> {
    let mut d = Runner::new(name);

    // nodes
    node!(d, ox, "helios-3.0", 4, gb(4));
    node!(d, cr1, "debian-13.2", 4, gb(4));
    node!(d, cr2, "eos-4.35", 4, gb(4));

    // links
    let mut mac_counter = 0;
    let mut new_mac = || {
        mac_counter += 1;
        format!("a8:40:25:00:00:{mac_counter:02}")
    };

    d.softnpu_link(ox, cr1, Some(new_mac()), None);
    d.softnpu_link(ox, cr2, Some(new_mac()), None);

    d.default_ext_link(ox)?;
    d.default_ext_link(cr1)?;
    d.default_ext_link(cr2)?;

    d.mount("cargo-bay", "/opt/cargo-bay", ox)?;
    d.mount("cargo-bay", "/opt/cargo-bay", cr1)?;
    d.mount("cargo-bay", "/opt/cargo-bay", cr2)?;

    Ok(Trio {
        d,
        ox: MgdNode(ox),
        cr1: FrrNode(cr1),
        cr2: EosNode(cr2),
    })
}
