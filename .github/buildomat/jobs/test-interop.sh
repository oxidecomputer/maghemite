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
#: [dependencies.image]
#: job = "image"
#:

set -x
set -e

cargo --version
rustc --version

banner 'inputs'

find /input -ls

banner 'setup'

tar xvfz /input/build-interop/work/interop.tar.gz

tar xvfz /input/image/out/mgd.tar.gz
for bin in mgadm mgd; do
	mv "image/root/opt/oxide/mgd/bin/$bin" "interop/cargo-bay/mgd/$bin"
done

banner 'launch'

cd interop
pfexec ./interop launch

banner 'test'

cargo nextest run
cp *.log /work/
