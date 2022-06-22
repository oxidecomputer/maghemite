// Copyright 2021 Oxide Computer Company

use libfalcon::{
    cli::{run, RunMode},
    error::Error,
    unit::gb,
    Runner,
};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut d = Runner::new("duo");

    // nodes
    let r0 = d.node("r0", "helios-1.0", 4, gb(4));
    let r1 = d.node("r1", "helios-1.0", 4, gb(4));

    d.mount("./cargo-bay", "/opt/cargo-bay", r0)?;
    d.mount("./cargo-bay", "/opt/cargo-bay", r1)?;

    // links
    d.link(r0, r1);

    match run(&mut d).await? {
        RunMode::Launch => {
            //d.exec(r0, "ipadm create-addr -t -T addrconf vioif0/v6").await?;
            //d.exec(r1, "ipadm create-addr -t -T addrconf vioif0/v6").await?;
            Ok(())
        }
        _ => Ok(()),
    }
}
