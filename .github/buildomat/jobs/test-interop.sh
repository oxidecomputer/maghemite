#!/bin/bash
#:
#: name = "test-interop"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: access_repos = [
#:   "oxidecomputer/testbed",
#: ]
#: output_rules = [
#:   "/work/*",
#: ]
#:
#: [dependencies.image]
#: job = "image"
#:

set -x
set -e

cargo --version
rustc --version

cargo install cargo-nextest
pfexec pkg install protobuf

banner "testbed setup"
git clone https://github.com/oxidecomputer/testbed
cd testbed/interop
mkdir image
cd image
cp /input/image/out/mgd.tar.gz .
tar xzvf mgd.tar.gz
cd ..
cp image/root/opt/oxide/mgd/bin/{mgd,mgadm} cargo-bay/mgd/
cargo build

banner "collect interface info"
ipadm
dladm
netstat -cran

banner "start topology"
pfexec ./interop launch

banner "test-interop"
cargo nextest run
cp *.log /work/
