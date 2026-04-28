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
pfexec cargo nextest run -p bgp -p bgp-types -p bgp-types-versions
cp *.log /work/
popd

pushd mgd
pfexec cargo nextest run -p mgd -p mg-types -p mg-types-versions
cp *.log /work/
popd
