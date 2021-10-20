// Copyright 2021 Oxide Computer Company

use libfalcon::{cli::{run, RunMode}, Deployment};
use anyhow::{Result};

fn main() {

    println!("{:?}", do_run());

}

fn do_run() -> Result<()> {

    let mut d = Deployment::new("quartet");

    // nodes
    let r0 = d.zone("r0");
    let r1 = d.zone("r1");
    let h0 = d.zone("h0");
    let h1 = d.zone("h1");

    d.mount("..", "/opt/maghemite", r0)?;
    d.mount("..", "/opt/maghemite", r1)?;
    d.mount("..", "/opt/maghemite", h0)?;
    d.mount("..", "/opt/maghemite", h1)?;

    // links
    d.link(r0, h0);
    d.link(r0, h1);
    d.link(r1, h0);
    d.link(r1, h1);

    match run(&mut d) {
        RunMode::Launch => {
           d.exec(r0, "ipadm create-addr -t -T addrconf quartet_r0_vnic0/v6")?;
           d.exec(r0, "ipadm create-addr -t -T addrconf quartet_r0_vnic1/v6")?;
           d.exec(r0, "routeadm -e ipv6-forwarding")?;
           d.exec(r0, "routeadm -u")?;

           d.exec(r1, "ipadm create-addr -t -T addrconf quartet_r1_vnic0/v6")?;
           d.exec(r1, "ipadm create-addr -t -T addrconf quartet_r1_vnic1/v6")?;
           d.exec(r1, "routeadm -e ipv6-forwarding")?;
           d.exec(r1, "routeadm -u")?;

           d.exec(h0, "ipadm create-addr -t -T addrconf quartet_h0_vnic0/v6")?;
           d.exec(h0, "ipadm create-addr -t -T addrconf quartet_h0_vnic1/v6")?;
           /*XXX via automatic underlay init now
           d.exec(h0,
               "ipadm create-addr -t -T static \
               -a fd00:1701:d:101::1/64 lo0/underlay")?;
           */

           d.exec(h1, "ipadm create-addr -t -T addrconf quartet_h1_vnic0/v6")?;
           d.exec(h1, "ipadm create-addr -t -T addrconf quartet_h1_vnic1/v6")?;
           /*XXX via automatic underlay init now
           d.exec(h1,
               "ipadm create-addr -t -T \
               static -a fd00:1701:d:102::1/64 lo0/underlay")?;
           */
           Ok(())
        }
        _ => Ok(()),
    }

}
