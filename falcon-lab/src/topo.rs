//! Testing topologies

use anyhow::Result;
use libfalcon::{Runner, node, unit::gb};

use crate::{
    ddm::DdmNode,
    eos::EosNode,
    frr::FrrNode,
    juniper::JuniperNode,
    mgd::MgdNode,
    scenario::{DdmTrioScenario, InteropScenario, MgdDuoScenario},
};

pub(crate) trait Topology: Sized {
    type Scenario;

    fn build(scenario: Self::Scenario) -> Result<Self>;
    fn runner_mut(&mut self) -> &mut Runner;
}

pub struct MgdDuo {
    pub d: Runner,
    pub ox1: MgdNode,
    pub ox2: MgdNode,
}

impl Topology for MgdDuo {
    type Scenario = MgdDuoScenario;

    fn build(scenario: MgdDuoScenario) -> Result<Self> {
        let mut d = Runner::new(scenario.name());

        node!(d, ox1, "helios-3.0", 4, gb(4));
        node!(d, ox2, "helios-3.0", 4, gb(4));

        d.link(ox1, ox2);

        d.default_ext_link(ox1)?;
        d.default_ext_link(ox2)?;

        d.mount("cargo-bay", "/opt/cargo-bay", ox1)?;
        d.mount("cargo-bay", "/opt/cargo-bay", ox2)?;

        Ok(Self {
            d,
            ox1: MgdNode(ox1),
            ox2: MgdNode(ox2),
        })
    }

    fn runner_mut(&mut self) -> &mut Runner {
        &mut self.d
    }
}

pub struct DdmTrio {
    pub d: Runner,
    pub hub: DdmNode,
    pub peer1: DdmNode,
    pub peer2: DdmNode,
}

impl Topology for DdmTrio {
    type Scenario = DdmTrioScenario;

    /// Three DDM routers in a star. The hub's first two interfaces connect to
    /// one leaf each, allowing their FSM lifecycles to be controlled
    /// independently.
    fn build(scenario: DdmTrioScenario) -> Result<Self> {
        let mut d = Runner::new(scenario.name());

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

        Ok(Self {
            d,
            hub: DdmNode(hub),
            peer1: DdmNode(peer1),
            peer2: DdmNode(peer2),
        })
    }

    fn runner_mut(&mut self) -> &mut Runner {
        &mut self.d
    }
}

pub struct Interop {
    pub d: Runner,
    pub ox: MgdNode,
    pub peer: MgdNode,
    pub cr1: FrrNode,
    pub cr2: EosNode,
    pub cr3: JuniperNode,
}

impl Topology for Interop {
    type Scenario = InteropScenario;

    fn build(scenario: InteropScenario) -> Result<Self> {
        let mut d = Runner::new(scenario.name());

        node!(d, ox, "helios-3.0", 4, gb(4));
        node!(d, cr1, "debian-13.2", 4, gb(4));
        node!(d, cr2, "eos-4.35", 4, gb(4));
        node!(d, cr3, "junos-23.2", 4, gb(4));
        node!(d, peer, "helios-3.0", 4, gb(4));

        let mut mac_counter = 0;
        let mut new_mac = || {
            mac_counter += 1;
            format!("a8:40:25:00:00:{mac_counter:02}")
        };

        d.softnpu_link(ox, cr1, Some(new_mac()), None);
        d.softnpu_link(ox, cr2, Some(new_mac()), None);
        d.softnpu_link(ox, cr3, Some(new_mac()), None);
        d.softnpu_link(ox, peer, Some(new_mac()), None);

        d.default_ext_link(ox)?;
        d.default_ext_link(cr1)?;
        d.default_ext_link(cr2)?;
        d.default_ext_link(cr3)?;
        d.default_ext_link(peer)?;

        d.mount("cargo-bay", "/opt/cargo-bay", ox)?;
        d.mount_linux("cargo-bay", "/opt/cargo-bay", cr1)?;
        d.mount("cargo-bay", "/opt/cargo-bay", cr2)?;
        d.mount_linux("cargo-bay", "/opt/cargo-bay", cr3)?;
        d.mount("cargo-bay", "/opt/cargo-bay", peer)?;
        // The Junos image mounts cargo-bay and applies staged configuration
        // from guest-side systemd services. Keep the 9p device in the spec,
        // but avoid Falcon's serial-driven setup/mount path for this node.
        d.do_setup(cr3, false);

        Ok(Self {
            d,
            ox: MgdNode(ox),
            peer: MgdNode(peer),
            cr1: FrrNode(cr1),
            cr2: EosNode(cr2),
            cr3: JuniperNode(cr3),
        })
    }

    fn runner_mut(&mut self) -> &mut Runner {
        &mut self.d
    }
}
