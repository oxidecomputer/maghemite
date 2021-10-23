// Copyright 2021 Oxide Computer Company

use libfalcon::{cli::{run, RunMode}, error::Error, Deployment};

fn main() -> Result<(), Error> {

    let mut d = Deployment::new("duo");

    // nodes
    let r0 = d.zone("r0");
    let r1 = d.zone("r1");

    d.mount("..", "/opt/maghemite", r0)?;
    d.mount("..", "/opt/maghemite", r1)?;

    // links
    d.link(r0, r1);

    match run(&mut d) {
        Ok(mode) => match mode {
            RunMode::Launch => {
                d.exec(r0, "ipadm create-addr -t -T addrconf duo_r0_vnic0/v6")?;
                d.exec(r1, "ipadm create-addr -t -T addrconf duo_r1_vnic0/v6")?;
                Ok(())
            }
            RunMode::Destroy => Ok(()),
        }
        Err(e) => Err(e),
    }

}
