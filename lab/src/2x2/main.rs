// Copyright 2021 Oxide Computer Company

use libfalcon::{cli::run, error::Error, Runner, unit::gb};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut d = Runner::new("mg2x2");

    // routers
    let r0 = d.node("r0", "helios-1.0", 4, gb(4));
    let r1 = d.node("r1", "helios-1.0", 4, gb(4));
    let routers = [r0, r1];

    // hosts
    let h0 = d.node("h0", "helios-1.0", 4, gb(4));
    let h1 = d.node("h1", "helios-1.0", 4, gb(4));
    let hosts = [h0, h1];

    let all = [r0, r1, h0, h1];
    for node in all {
        d.mount("./cargo-bay", "/opt/cargo-bay", node)?;
    }

    // links
    for r in routers {
        for h in hosts {
            d.link(r, h);
        }
    }

    match run(&mut d).await? {
        _ => { Ok(()) }
    }
}
