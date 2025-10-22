#!/bin/bash
#:
#: name = "test-bgp"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#:

set -x
set -e

source .github/buildomat/test-common.sh
pushd bgp
cargo nextest run
cp *.log /work/
popd

pushd mgd
cargo nextest run
cp *.log /work/
popd
