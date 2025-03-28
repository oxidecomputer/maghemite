#!/bin/bash
#:
#: name = "test-rdb"
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

set -x
set -e

cargo --version
rustc --version

cargo install cargo-nextest

pushd rdb

cargo nextest run
cp *.log /work/
