#!/bin/bash
#:
#: name = "test-interop"
#: variety = "basic"
#: target = "lab-2.0-opte"
#: rust_toolchain = "stable"
#: skip_clone = true
#: output_rules = [
#:   "/work/*",
#: ]
#:
#: [dependencies.build-interop]
#: job = "build-interop"
#:

set -x
set -e

cargo --version
rustc --version

banner "setup"
ls -R /input
cp /input/build-interop/work/interop.tgz .
tar xzvf interop.tgz
cd interop

banner "launch"
pfexec ./interop launch

banner "test"
cargo nextest run
cp *.log /work/
