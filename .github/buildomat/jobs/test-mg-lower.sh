#!/bin/bash
#:
#: name = "test-mg-lower"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"

set -x
set -e

source .github/buildomat/test-common.sh
pushd mg-lower
cargo nextest run
