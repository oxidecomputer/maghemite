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
#:   "=/work/interop.tar.gz",
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
cargo build -p interop-lab

banner 'archive'
tar cvfz /work/interop.tar.gz \
    interop \
    target/debug/wrangler \
    target/debug/interop
