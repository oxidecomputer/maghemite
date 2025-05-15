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
cargo nextest run
cp *.log /work/
popd

pushd mgd
cargo nextest run
cp *.log /work/
popd
