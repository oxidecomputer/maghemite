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

banner "collect interface info"
ipadm
dladm
netstat -cran

banner "setup interop topology"
cp /input/test-interop/out/interop.tgz .
tar xzvf interop.tgz
cd interop

banner "launch interop topology"
pfexec ./interop launch

banner "start interop test"
cargo nextest run
cp *.log /work/
