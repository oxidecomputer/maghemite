#!/bin/bash
#:
#: name = "test-bgp"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -o xtrace

cargo --version
rustc --version

cargo install cargo-nextest

pushd bgp

# XXX remove this once we start actually asserting things in this test, for now
# just dump the logs in CI
cargo nextest run bgp_basics --no-capture

cargo nextest run
