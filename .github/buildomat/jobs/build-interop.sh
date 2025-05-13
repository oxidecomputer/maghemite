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
#:   "=/work/testbed.tar.gz",
#: ]
#:

set -x
set -e

cargo --version
rustc --version

cargo install cargo-nextest
pfexec pkg install protobuf git

banner 'clone'
git clone https://github.com/oxidecomputer/testbed

banner 'build'
cd testbed
cargo build \
    -p interop-lab \
    -p wrangler
cargo build --tests

banner 'prep'

mkdir out
cp target/debug/{interop,wrangler} out
# grab just the file ending in the hash, not the file ending in ".d"
TEST=$(ls ../target/debug/deps/baseline-* | egrep -v '.*\.d$')
cp $TEST out
cd ..

banner 'archive'

tar cvzXf <(echo testbed/target) \
    /work/testbed.tar.gz \
    testbed
