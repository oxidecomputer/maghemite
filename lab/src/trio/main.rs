// Copyright 2021 Oxide Computer Company

use libfalcon::{cli::{run, RunMode}, error::Error, Runner};

#[tokio::main]
async fn main() -> Result<(), Error> {

    let mut d = Runner::new("trio");

    // nodes
    let r = d.node("r", "helios");
    let h0 = d.node("h0", "helios");
    let h1 = d.node("h1", "helios");

    d.mount("..", "/opt/maghemite", r)?;
    d.mount("..", "/opt/maghemite", h0)?;
    d.mount("..", "/opt/maghemite", h1)?;

    // links
    d.link(r, h0);
    d.link(r, h1);

    match run(&mut d).await? {
        RunMode::Launch => {
            d.exec(r, "ipadm create-addr -t -T addrconf trio_r_vnic0/v6")?;
            d.exec(r, "ipadm create-addr -t -T addrconf trio_r_vnic1/v6")?;
            d.exec(h0, "ipadm create-addr -t -T addrconf trio_h0_vnic0/v6")?;
            d.exec(h1, "ipadm create-addr -t -T addrconf trio_h1_vnic0/v6")?;
            Ok(())
        },
        RunMode::Destroy => Ok(()),
    }

}
