#!/bin/bash
#:
#: name = "check-style"
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
cargo fmt --version

banner "check fmt"
ptime -m cargo fmt -- --check
