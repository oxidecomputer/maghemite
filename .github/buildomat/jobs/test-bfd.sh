#!/bin/bash
#:
#: name = "test-bfd"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite-os",
#: ]
#:

set -o xtrace
set -o errexit
set -o pipefail

cargo --version
rustc --version

cargo install cargo-nextest

banner bfd
cargo nextest run -p bfd --nocapture

