// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exposes the dendrite revision that the workspace pins `dpd-client` to as
//! the `DENDRITE_COMMIT` environment variable at compile time, so falcon-lab
//! installs the same dendrite in the softnpu VM that it talks to via
//! `dpd-client`.

use cargo_toml::Manifest;

#[allow(
    clippy::disallowed_macros,
    reason = "build scripts talk to cargo over stdout"
)]
fn main() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml");
    let manifest =
        Manifest::from_path(path).expect("read workspace Cargo.toml");
    let rev = manifest
        .workspace
        .expect("workspace Cargo.toml has a [workspace] table")
        .dependencies
        .get("dpd-client")
        .expect("workspace depends on dpd-client")
        .git_rev()
        .expect("dpd-client is pinned to a git rev")
        .to_owned();

    println!("cargo::rustc-env=DENDRITE_COMMIT={rev}");
    println!("cargo::rerun-if-changed={path}");
}
