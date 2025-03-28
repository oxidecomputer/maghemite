#!/bin/bash
#:
#: name = "test-ddm-quartet"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite-os",
#: ]
#:

source .github/buildomat/test-ddm-common.sh

#
# quartest tests
#

banner "quartet"
pfexec cargo test --release -p mg-tests test_quartet -- --nocapture
