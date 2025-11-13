#!/bin/bash
#:
#: name = "test-rdb"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#:   "/tmp/*.db",
#: ]
#:

set -x
set -e

source .github/buildomat/test-common.sh
pushd rdb
cargo nextest run
cp *.log /work/
