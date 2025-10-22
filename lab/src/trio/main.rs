// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2021 Oxide Computer Company

use libfalcon::Runner;
use libfalcon::cli::RunMode;
use libfalcon::cli::run;
use libfalcon::error::Error;
use libfalcon::unit::gb;

fn main() -> Result<(), Error> {
    oxide_tokio_rt::run(main_impl())
}

async fn main_impl() -> Result<(), Error> {
    let mut d = Runner::new("trio");

    // nodes
    let r = d.node("r", "helios-1.0", 4, gb(4));
    let h0 = d.node("h0", "helios-1.0", 4, gb(4));
    let h1 = d.node("h1", "helios-1.0", 4, gb(4));

    d.mount("./cargo-bay", "/opt/cargo-bay", r)?;
    d.mount("./cargo-bay", "/opt/cargo-bay", h0)?;
    d.mount("./cargo-bay", "/opt/cargo-bay", h1)?;

    // links
    d.link(r, h0);
    d.link(r, h1);

    match run(&mut d).await? {
        RunMode::Launch => {
            d.exec(r, "ipadm create-addr -t -T addrconf vioif0/v6")
                .await?;
            d.exec(r, "ipadm create-addr -t -T addrconf vioif1/v6")
                .await?;
            d.exec(h0, "ipadm create-addr -t -T addrconf vioif0/v6")
                .await?;
            d.exec(h1, "ipadm create-addr -t -T addrconf vioif0/v6")
                .await?;
            Ok(())
        }
        _ => Ok(()),
    }
}
