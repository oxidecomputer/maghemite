// Copyright 2021 Oxide Computer Company

use libfalcon::{cli::{run, RunMode}, error::Error, Deployment};

fn main() {

    println!("{:?}", do_run());

}

fn do_run() -> Result<(), Error> {

    let mut d = Deployment::new("trio");

    // nodes
    let r = d.zone("r");
    let h0 = d.zone("h0");
    let h1 = d.zone("h1");

    d.mount("..", "/opt/maghemite", r)?;
    d.mount("..", "/opt/maghemite", h0)?;
    d.mount("..", "/opt/maghemite", h1)?;

    // links
    d.link(r, h0);
    d.link(r, h1);

    match run(&mut d) {
        Ok(mode) => match mode {
            RunMode::Launch => {
                d.exec(r, "ipadm create-addr -t -T addrconf trio_r_vnic0/v6")?;
                d.exec(r, "ipadm create-addr -t -T addrconf trio_r_vnic1/v6")?;
                d.exec(h0, "ipadm create-addr -t -T addrconf trio_h0_vnic0/v6")?;
                d.exec(h1, "ipadm create-addr -t -T addrconf trio_h1_vnic0/v6")?;
                Ok(())
            },
            RunMode::Destroy => Ok(()),
        }
        Err(e) => Err(e),
    }

}
