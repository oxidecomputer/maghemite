#!/bin/bash
#:
#: name = "test-proptest"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#:   "/work/proptest-regressions/**/*",
#:   "/tmp/*.db",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -x
set -e

source .github/buildomat/test-common.sh

# Run property-based tests with high intensity (default is 256)
export PROPTEST_CASES=1000000

run_crate_proptests() {
    local crate="$1"

    pushd "${crate}"
    cargo nextest run --lib proptest
    cp ./*.log /work/ 2>/dev/null || true

    if [[ -d proptest-regressions ]]; then
        mkdir -p "/work/proptest-regressions/${crate}"
        cp -R proptest-regressions/. "/work/proptest-regressions/${crate}/"
    fi

    popd
}

run_crate_proptests rdb

run_crate_proptests bgp

run_crate_proptests unnumbered
