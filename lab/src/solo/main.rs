// Copyright 2021 Oxide Computer Company

use libfalcon::cli::run;
use libfalcon::error::Error;
use libfalcon::unit::gb;
use libfalcon::Runner;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut d = Runner::new("mgsolo");

    // nodes
    let han = d.node("han", "helios-1.0", 4, gb(4));
    d.mount("./cargo-bay", "/opt/cargo-bay", han)?;

    // links
    d.ext_link("igb0", han);

    run(&mut d).await?;

    Ok(())
}
