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

status=0

# Run a crate's proptests. A failure is recorded without aborting
# so that later crates can still run and their failing seeds get collected.
#
# Each crate's proptest-regressions tree is copied under its own name
# because seed files are keyed by source file path and could collide across
# crates.
run_proptests() {
	local name=$1
	local dir=$2
	pushd "${dir}"
	PROPTEST_CASES=1000000 cargo nextest run --lib proptest || status=$?
	cp ./*.log /work/ 2>/dev/null || true
	if [[ -d proptest-regressions ]]; then
		mkdir -p "/work/proptest-regressions/${name}"
		cp -r proptest-regressions/. "/work/proptest-regressions/${name}/"
	fi
	popd
}

run_proptests rdb rdb
run_proptests bgp bgp
run_proptests mg-api-types mg-api-types/versions

exit "${status}"
