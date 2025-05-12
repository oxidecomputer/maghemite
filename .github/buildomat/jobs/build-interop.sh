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

banner 'info'

ls -a -R interop/.falcon

banner 'archive'
mkdir out
cp target/debug/{interop,wrangler} out
cd ..
# TODO: DOES THIS COPY HIDDEN DIRECTORIES? (testbed/.falcon)
tar cvzXf <(echo testbed/target) \
    /work/testbed.tar.gz \
    testbed
