//! Testing topologies

use anyhow::Result;
use libfalcon::{Runner, node, unit::gb};

use crate::{
    eos::EosNode,
    frr::FrrNode,
    juniper::JuniperNode,
    mgd::MgdNode,
    scenario::{BgpAddPathScenario, InteropScenario, MgdDuoScenario},
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

#[derive(Copy, Clone)]
pub enum AddPathSpeaker {
    Frr(FrrNode),
    Arista(EosNode),
    Juniper(JuniperNode),
}

/// One receiving mgd peer, a scenario-selected transit router, and two FRR origins.
pub struct BgpAddPath {
    pub d: Runner,
    pub ox: MgdNode,
    pub transit: AddPathSpeaker,
    pub frr1: FrrNode,
    pub frr2: FrrNode,
}

impl Topology for BgpAddPath {
    type Scenario = BgpAddPathScenario;

    fn build(scenario: BgpAddPathScenario) -> Result<Self> {
        let mut d = Runner::new(scenario.name());

        let image = match scenario {
            BgpAddPathScenario::Bare | BgpAddPathScenario::Frr => "debian-13.2",
            BgpAddPathScenario::Arista => "eos-4.35",
            BgpAddPathScenario::Juniper => "junos-23.2",
        };
        node!(d, ox, "helios-3.0", 4, gb(4));
        node!(d, transit, image, 4, gb(4));
        node!(d, frr1, "debian-13.2", 4, gb(4));
        node!(d, frr2, "debian-13.2", 4, gb(4));

        // Direct links suffice for this control-plane test. With one 9p
        // mount and no SoftNPU devices, Debian NICs start at enp0s6.
        d.link(ox, transit);
        d.link(transit, frr1);
        d.link(transit, frr2);

        d.default_ext_link(ox)?;
        d.mount("cargo-bay", "/opt/cargo-bay", ox)?;
        for peer in [frr1, frr2] {
            d.default_ext_link(peer)?;
            d.mount_linux("cargo-bay", "/opt/cargo-bay", peer)?;
        }
        d.default_ext_link(transit)?;
        let transit = match scenario {
            BgpAddPathScenario::Bare | BgpAddPathScenario::Frr => {
                d.mount_linux("cargo-bay", "/opt/cargo-bay", transit)?;
                AddPathSpeaker::Frr(FrrNode(transit))
            }
            BgpAddPathScenario::Arista => {
                d.mount("cargo-bay", "/opt/cargo-bay", transit)?;
                AddPathSpeaker::Arista(EosNode(transit))
            }
            BgpAddPathScenario::Juniper => {
                d.mount_linux("cargo-bay", "/opt/cargo-bay", transit)?;
                // The image's services mount cargo-bay and apply staged config.
                d.do_setup(transit, false);
                AddPathSpeaker::Juniper(JuniperNode(transit))
            }
        };

        Ok(Self {
            d,
            ox: MgdNode(ox),
            transit,
            frr1: FrrNode(frr1),
            frr2: FrrNode(frr2),
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
