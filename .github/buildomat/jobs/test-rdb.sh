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
pfexec pkg install clang-15
curl -sSfL --retry 10 https://get.nexte.st/"$NEXTEST_VERSION"/"$PLATFORM" | gunzip | tar -xvf - -C ~/.cargo/bin

pushd rdb

cargo nextest run
cp *.log /work/
