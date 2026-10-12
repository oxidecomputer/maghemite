//! Testing topologies

use anyhow::Result;
use libfalcon::{NodeRef, Runner, node, unit::gb};

use crate::{
    bird::BirdNode,
    eos::EosNode,
    frr::FrrNode,
    juniper::JuniperNode,
    mgd::MgdNode,
    scenario::{
        Interop3LinkScenario, InteropScenario, MgdDuoScenario,
        SpineLeafScenario,
    },
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

pub struct Interop {
    pub d: Runner,
    pub ox: MgdNode,
    pub peer: MgdNode,
    pub cr1: FrrNode,
    pub cr2: EosNode,
    pub cr3: JuniperNode,
    pub bird: BirdNode,
}

pub struct Interop3Link {
    pub d: Runner,
    pub ox: MgdNode,
    pub peer: MgdNode,
    pub cr1: FrrNode,
    pub cr2: EosNode,
    pub cr3: JuniperNode,
    pub bird: BirdNode,
}

struct InteropNodes {
    d: Runner,
    ox: NodeRef,
    peer: NodeRef,
    cr1: NodeRef,
    cr2: NodeRef,
    cr3: NodeRef,
    bird: NodeRef,
}

fn build_interop(name: &str, links_per_peer: usize) -> Result<InteropNodes> {
    let mut d = Runner::new(name);

    node!(d, ox, "helios-3.0", 4, gb(4));
    node!(d, cr1, "debian-13.2", 4, gb(4));
    node!(d, cr2, "eos-4.35", 4, gb(4));
    node!(d, cr3, "junos-23.2", 4, gb(4));
    node!(d, peer, "helios-3.0", 4, gb(4));
    node!(d, bird, "bird2", 4, gb(4));

    let mut mac_counter = 0;
    let mut new_mac = || {
        mac_counter += 1;
        format!("a8:40:25:00:00:{mac_counter:02}")
    };

    for remote in [cr1, cr2, cr3, peer] {
        for _ in 0..links_per_peer {
            d.softnpu_link(ox, remote, Some(new_mac()), None);
        }
    }
    // Append BIRD: existing DUT ports and remote NIC indices stay unchanged.
    for index in 0..links_per_peer {
        d.softnpu_link(ox, bird, Some(BirdNode::data_mac(index)), None);
    }

    d.default_ext_link(ox)?;
    d.default_ext_link(cr1)?;
    d.default_ext_link(cr2)?;
    d.default_ext_link(cr3)?;
    d.default_ext_link(peer)?;
    d.default_ext_link(bird)?;

    d.mount("cargo-bay", "/opt/cargo-bay", ox)?;
    d.mount_linux("cargo-bay", "/opt/cargo-bay", cr1)?;
    d.mount("cargo-bay", "/opt/cargo-bay", cr2)?;
    d.mount_linux("cargo-bay", "/opt/cargo-bay", cr3)?;
    d.mount("cargo-bay", "/opt/cargo-bay", peer)?;
    d.mount_linux("cargo-bay", "/opt/cargo-bay", bird)?;
    // The Junos image mounts cargo-bay and applies staged configuration
    // from guest-side systemd services. Keep the 9p device in the spec,
    // but avoid Falcon's serial-driven setup/mount path for this node.
    d.do_setup(cr3, false);

    Ok(InteropNodes {
        d,
        ox,
        peer,
        cr1,
        cr2,
        cr3,
        bird,
    })
}

impl Topology for Interop {
    type Scenario = InteropScenario;

    fn build(scenario: InteropScenario) -> Result<Self> {
        let nodes = build_interop(scenario.name(), 1)?;
        Ok(Self {
            d: nodes.d,
            ox: MgdNode(nodes.ox),
            peer: MgdNode(nodes.peer),
            cr1: FrrNode(nodes.cr1),
            cr2: EosNode(nodes.cr2),
            cr3: JuniperNode(nodes.cr3),
            bird: BirdNode(nodes.bird),
        })
    }

    fn runner_mut(&mut self) -> &mut Runner {
        &mut self.d
    }
}

impl Topology for Interop3Link {
    type Scenario = Interop3LinkScenario;

    fn build(scenario: Interop3LinkScenario) -> Result<Self> {
        let nodes = build_interop(scenario.name(), 3)?;
        Ok(Self {
            d: nodes.d,
            ox: MgdNode(nodes.ox),
            peer: MgdNode(nodes.peer),
            cr1: FrrNode(nodes.cr1),
            cr2: EosNode(nodes.cr2),
            cr3: JuniperNode(nodes.cr3),
            bird: BirdNode(nodes.bird),
        })
    }

    fn runner_mut(&mut self) -> &mut Runner {
        &mut self.d
    }
}

pub struct SpineLeaf {
    pub d: Runner,
    pub leaves: [MgdNode; 2],
    pub frr: FrrNode,
    pub eos: EosNode,
    pub junos: JuniperNode,
    pub bird: BirdNode,
}

impl Topology for SpineLeaf {
    type Scenario = SpineLeafScenario;

    fn build(scenario: SpineLeafScenario) -> Result<Self> {
        let mut d = Runner::new(scenario.name());
        node!(d, ox1, "helios-3.0", 4, gb(4));
        node!(d, ox2, "helios-3.0", 4, gb(4));
        node!(d, frr, "debian-13.2", 4, gb(4));
        node!(d, eos, "eos-4.35", 4, gb(4));
        node!(d, junos, "junos-23.2", 4, gb(4));
        node!(d, bird, "bird2", 4, gb(4));

        // Each leaf's qsfp0..3 face FRR, EOS, Junos, BIRD respectively.
        // Each spine's first two data NICs face ox1 and ox2 respectively.
        for (leaf_index, leaf) in [ox1, ox2].into_iter().enumerate() {
            for (port, spine) in [frr, eos, junos, bird].into_iter().enumerate()
            {
                let mac = if port == 3 {
                    BirdNode::data_mac(leaf_index)
                } else {
                    format!("a8:40:25:02:{leaf_index:02x}:{port:02x}")
                };
                d.softnpu_link(leaf, spine, Some(mac), None);
            }
        }
        for node in [ox1, ox2, frr, eos, junos, bird] {
            d.default_ext_link(node)?;
        }
        for node in [ox1, ox2, eos] {
            d.mount("cargo-bay", "/opt/cargo-bay", node)?;
        }
        for node in [frr, junos, bird] {
            d.mount_linux("cargo-bay", "/opt/cargo-bay", node)?;
        }
        d.do_setup(junos, false);
        Ok(Self {
            d,
            leaves: [MgdNode(ox1), MgdNode(ox2)],
            frr: FrrNode(frr),
            eos: EosNode(eos),
            junos: JuniperNode(junos),
            bird: BirdNode(bird),
        })
    }

    fn runner_mut(&mut self) -> &mut Runner {
        &mut self.d
    }
}
