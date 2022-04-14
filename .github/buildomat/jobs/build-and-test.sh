#!/bin/bash
#:
#: name = "build-and-test"
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

banner "build"
ptime -m cargo build
ptime -m cargo build --release

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/ddmd /work/$x/ddmd
    cp target/$x/ddmadm /work/$x/ddmadm
done

banner "test"

export RUST_LOG=trace

banner "rdp"
pfexec cargo test rs_send_recv

banner "peer"
pfexec cargo test peer_session1

banner "dpx x2"
pfexec cargo test rs_dpx_x2

banner "dpx 1x2"
pfexec cargo test rs_dpx_1x2
