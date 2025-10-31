#!/bin/bash
#:
#: name = "test-proptest"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#:   "/work/proptest-regressions/*",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -x
set -e

# NOTE: This version should be in sync with the recommended version in
# .config/nextest.toml. (Maybe build an automated way to pull the recommended
# version in the future.)
NEXTEST_VERSION='0.9.97'
PLATFORM='illumos'

cargo --version
rustc --version
cargo install cargo-nextest --version "$NEXTEST_VERSION"

source .github/buildomat/test-common.sh

# Run property-based tests with high intensity (default is 256)

# RDB proptest suite
pushd rdb
PROPTEST_CASES=1000000 cargo nextest run --lib types_proptest
cp *.log /work/ 2>/dev/null || true
if [ -d proptest-regressions ]; then
    cp -r proptest-regressions /work/rdb-proptest-regressions
fi
popd

# BGP proptest suite
pushd bgp
PROPTEST_CASES=1000000 cargo nextest run --lib proptest
cp *.log /work/ 2>/dev/null || true
if [ -d proptest-regressions ]; then
    cp -r proptest-regressions /work/bgp-proptest-regressions
fi
popd
