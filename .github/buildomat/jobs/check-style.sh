#!/bin/bash
#:
#: name = "check-style"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly-2021-11-24"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#:   "oxidecomputer/falcon",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
cargo fmt --version

banner "check fmt"
ptime -m cargo fmt -- --check
