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

# Bare `-p rdb-types` is ambiguous: omicron transitively pins an upstream
# copy of rdb-types via mg-admin-client, leaving two rdb-types nodes in
# Cargo.lock. The Package ID Spec form (`path+file://<absolute-path>`)
# selects the local crate unambiguously.
pushd rdb
cargo nextest run \
    -p rdb \
    -p "path+file://$PWD/../rdb-types" \
    -p rdb-types-versions
cp *.log /work/
popd
