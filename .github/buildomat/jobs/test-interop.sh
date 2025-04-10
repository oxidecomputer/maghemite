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

banner "setup"
git clone https://github.com/oxidecomputer/testbed
cd testbed/interop
mkdir image
cd image
cp /input/image/mgd.tar.gz .
tar xzvf mgd.tar.gz
cp root/opt/oxide/mgd/bin/{mgd,mgadm} cargo-bay/mgd/
cargo build

banner "start topology"
pfexec ./interop launch

banner "test-interop"
cargo nextest run
cp *.log /work/
