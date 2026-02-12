//! Testing topologies

use anyhow::Result;
use libfalcon::{Runner, node, unit::gb};

use crate::{eos::EosNode, frr::FrrNode, mgd::MgdNode};

pub struct Trio {
    pub d: Runner,
    pub ox: MgdNode,
    pub cr1: FrrNode,
    pub cr2: EosNode,
}

pub fn trio(name: &str) -> Result<Trio> {
    let mut d = Runner::new(name);

    // nodes
    node!(d, ox, "helios-2.9", 4, gb(4));
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
