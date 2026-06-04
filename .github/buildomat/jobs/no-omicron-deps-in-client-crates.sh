#!/bin/bash
#:
#: name = "no-omicron-deps-in-client-crates"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#:

# The client and api-types crates are consumed by omicron. Maghemite
# also consumes omicron. For the maghemite crates that omicron consumes
# we cannot have omicron dependencies as this leads to a hot mess for
# integration.

function omicron_dep_check {
  echo "checking $1"
  set -e
  pushd "$1"
  set +e
  tree_output=$(cargo tree -e normal --all-features)
  if grep omicron <<< "$tree_output"; then
    echo "$1 may not depend on omicron"
    exit 1
  fi
  popd
}

omicron_dep_check mg-admin-client
omicron_dep_check ddm-admin-client
omicron_dep_check ddm-api-types
omicron_dep_check mg-api-types
omicron_dep_check mg-api-types/versions
