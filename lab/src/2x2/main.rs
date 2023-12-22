// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2021 Oxide Computer Company

use libfalcon::cli::run;
use libfalcon::error::Error;
use libfalcon::unit::gb;
use libfalcon::Runner;

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

    let _ = run(&mut d).await?;

    Ok(())
}
