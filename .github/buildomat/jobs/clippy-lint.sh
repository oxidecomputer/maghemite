#!/bin/bash
#:
#: name = "clippy-lint"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version
cargo clippy -- --version

banner "clippy"
ptime -m cargo clippy -- -D warnings -A clippy::style
