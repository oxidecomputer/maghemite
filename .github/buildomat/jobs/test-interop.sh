#!/bin/bash
#:
#: name = "test-interop"
#: variety = "basic"
#: target = "lab-2.0-opte"
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

banner 'inputs'

find /input -ls

banner 'setup'

tar xvfz /input/build-interop/work/testbed.tar.gz

mkdir -p image/mgd
(cd image/mgd && tar xvfz /input/image/out/mgd.tar.gz)
for bin in mgadm mgd; do
	mv "image/mgd/root/opt/oxide/mgd/bin/$bin" \
	    "interop/cargo-bay/mgd/$bin"
done
mkdir -p target/debug
mv out/{interop,wrangler} target/debug

banner 'launch'

cd testbed/interop
pfexec ./interop launch

banner 'test'

cargo nextest run
cp *.log /work/
