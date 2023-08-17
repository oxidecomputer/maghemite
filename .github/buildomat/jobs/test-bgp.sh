#!/bin/bash
#:
#: name = "test-bgp"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -x
set -e

cargo --version
rustc --version

cargo install cargo-nextest

pushd bgp

# XXX remove this once we start actually asserting things in this test, for now
# just dump the logs in CI
cargo nextest run bgp_basics

cargo nextest run
cp *.log /work/
