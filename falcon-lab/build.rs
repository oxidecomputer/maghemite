// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::Write;
use std::path::PathBuf;

fn main() {
    let mut out = std::io::stdout().lock();
    let lock = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"),
    )
    .join("../Cargo.lock");
    writeln!(out, "cargo:rerun-if-changed={}", lock.display())
        .expect("write to stdout");

    let contents =
        std::fs::read_to_string(&lock).expect("read workspace Cargo.lock");
    let mut revs = contents
        .split("[[package]]")
        .filter(|pkg| pkg.lines().any(|line| line == r#"name = "dpd-client""#))
        .filter_map(|pkg| {
            pkg.lines()
                .find_map(|line| line.strip_prefix(r#"source = "git+"#))
                .and_then(|src| src.trim_end_matches('"').rsplit_once('#'))
                .map(|(_, rev)| rev.to_owned())
        })
        .collect::<Vec<_>>();
    revs.sort();
    revs.dedup();

    match revs.as_slice() {
        [] => {}
        [rev] => writeln!(out, "cargo:rustc-env=DPD_CLIENT_COMMIT={rev}")
            .expect("write to stdout"),
        _ => panic!("multiple dpd-client git revs in Cargo.lock: {revs:?}"),
    }
}
