// Copyright 2021 Oxide Computer Company

use anyhow::{anyhow, Result};
use std::thread;
use ron::de::from_str;
use icmpv6::{RDPMessage, ICMPv6Packet};

#[test]
#[ignore]
fn duot_rdp() -> Result<()> {

    // create testing topology
    let mut d = libfalcon::Deployment::new("duot");
    let r0 = d.zone("r0");
    let r1 = d.zone("r1");
    d.link(r0, r1);

    // mount in software
    d.mount("../..", "/opt/maghemite", r0)?;
    d.mount("../..", "/opt/maghemite", r1)?;

    // launch topology
    d.launch()?;

    // create link local ipv6 addresses
    d.exec(r0, "ipadm create-addr -T addrconf duot_r0_vnic0/v6")?;
    d.exec(r1, "ipadm create-addr -T addrconf duot_r1_vnic0/v6")?;

    // wait for addresses to become ready
    let mut retries = 0;
    loop {
        let state =
            d.exec(r1, "ipadm show-addr -po state duot_r1_vnic0/v6")?;
        if state == "ok" {
            break;
        }
        retries += 1;
        if retries >= 10 {
            return Err(anyhow!(
                    "timed out waiting for duot_r1_vnic0/v6"
            ));
        }
        thread::sleep(std::time::Duration::from_secs(1))
    }

    // start the rdpx watcher, this watches for RDP solicitations and
    // advertisements. When an RDP message comes in, it's dumped to the console
    // in rusty object notation (RON). The -c flag indicates to exit after one
    // message is received.
    let rx = d.spawn(r1, "/opt/maghemite/target/debug/rdpx watch -c 1");

    // wait for `rdpx watch` process to start
    loop {
        match d.exec(r1, "pgrep rdpx") {
            Ok(_) => break,
            Err(_) => continue
        }
    }

    // run rdpx on r0 sending a solicitation
    d.exec(r0, "/opt/maghemite/target/debug/rdpx solicit")?;

    // wait for the receive channel on `rdpx watch` from r1 to light up.
    let out = rx.recv()??;

    // dump result for debugging
    println!("OUT: {}", out);

    // ensure what we got was in fact a solicitation
    let msg: RDPMessage = from_str(out.as_str())?;
    match msg.packet {
        ICMPv6Packet::RouterSolicitation(_) => {},
        _ => return Err(anyhow!("expected router solicitation")),
    };

    Ok(())

}

