// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use std::fs::create_dir_all;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = omicron_zone_package::config::parse("package-manifest.toml")?;

    let output_dir = Path::new("out");
    create_dir_all(output_dir)?;

    for (name, package) in cfg.packages {
        package.create(&name, output_dir).await?;
    }

    Ok(())
}
