#!/bin/bash
#:
#: name = "build"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly-2021-11-24"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#:   "oxidecomputer/falcon",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

pushd ddm-illumos

banner "build ddm-illumos"
ptime -m cargo build
ptime -m cargo build --release

popd

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/ddm-illumos /work/$x/ddm-illumos
done

banner "build ddmadm"
pushd ddmadm

ptime -m cargo build
ptime -m cargo build --release

popd

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/ddmadm /work/$x/ddmadm
done
