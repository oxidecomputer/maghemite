#!/bin/bash
#:
#: name = "test-proptest"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#:   "/work/proptest-regressions/*",
#:   "/tmp/*.db",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -x
set -e

source .github/buildomat/test-common.sh

# Run property-based tests with high intensity (default is 256)

# RDB proptest suite
pushd rdb
PROPTEST_CASES=1000000 cargo nextest run --lib proptest
cp ./*.log /work/ 2>/dev/null || true
if [[ -d proptest-regressions ]]; then
    cp -r proptest-regressions /work/rdb-proptest-regressions
fi
popd

# BGP proptest suite
pushd bgp
PROPTEST_CASES=1000000 cargo nextest run --lib proptest
cp ./*.log /work/ 2>/dev/null || true
if [[ -d proptest-regressions ]]; then
    cp -r proptest-regressions /work/bgp-proptest-regressions
fi
popd
