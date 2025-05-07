#!/bin/bash
#:
#: name = "build-interop"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: access_repos = [
#:   "oxidecomputer/testbed",
#: ]
#: output_rules = [
#:   "=/work/interop.tgz",
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
pfexec pkg install protobuf git

banner "build interop topology"
git clone https://github.com/oxidecomputer/testbed
cd testbed/interop
mkdir image
cd image
cp /input/image/out/mgd.tar.gz .
tar xzvf mgd.tar.gz
cd ..
cp image/root/opt/oxide/mgd/bin/{mgd,mgadm} cargo-bay/mgd/
cargo build
cd ..
tar czvf interop.tgz interop/
mv interop.tgz work/
