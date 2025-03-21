// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::anyhow;
use anyhow::Result;
use ddm::admin::api_description;
use semver::{BuildMetadata, Prerelease, Version};
use std::fs::File;

fn main() -> Result<()> {
    let api = api_description().map_err(|e| anyhow!("{}", e))?;
    let openapi = api.openapi(
        "DDM Admin",
        Version {
            major: 0,
            minor: 1,
            patch: 0,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        },
    );
    let mut out = File::create("ddm-admin.json")?;
    openapi.write(&mut out)?;
    Ok(())
}
