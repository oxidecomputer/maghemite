// Copyright 2021 Oxide Computer Company

use libfalcon::{cli::{run, RunMode}, error::Error, Runner};

#[tokio::main]
async fn main() -> Result<(), Error> {

    let mut d = Runner::new("quartet");

    // nodes
    let r0 = d.node("r0", "helios");
    let r1 = d.node("r1", "helios");
    let h0 = d.node("h0", "helios");
    let h1 = d.node("h1", "helios");

    d.mount("./cargo-bay", "/opt/cargo-bay", r0)?;
    d.mount("./cargo-bay", "/opt/cargo-bay", r1)?;
    d.mount("./cargo-bay", "/opt/cargo-bay", h0)?;
    d.mount("./cargo-bay", "/opt/cargo-bay", h1)?;

    // links
    d.link(r0, h0);
    d.link(r0, h1);
    d.link(r1, h0);
    d.link(r1, h1);

    match run(&mut d).await? {
        RunMode::Launch => {
            d.exec(r0, "ipadm create-addr -t -T addrconf vioif0/v6").await?;
            d.exec(r0, "ipadm create-addr -t -T addrconf vioif1/v6").await?;
            d.exec(r0, "routeadm -e ipv6-forwarding").await?;
            d.exec(r0, "routeadm -u").await?;

            d.exec(r1, "ipadm create-addr -t -T addrconf vioif0/v6").await?;
            d.exec(r1, "ipadm create-addr -t -T addrconf vioif1/v6").await?;
            d.exec(r1, "routeadm -e ipv6-forwarding").await?;
            d.exec(r1, "routeadm -u").await?;

            d.exec(h0, "ipadm create-addr -t -T addrconf vioif0/v6").await?;
            d.exec(h0, "ipadm create-addr -t -T addrconf vioif1/v6").await?;

            d.exec(h1, "ipadm create-addr -t -T addrconf vioif0/v6").await?;
            d.exec(h1, "ipadm create-addr -t -T addrconf vioif1/v6").await?;
            Ok(())
        },
        RunMode::Destroy => Ok(()),
    }

}
