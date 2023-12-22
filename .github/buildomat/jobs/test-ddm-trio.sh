#!/bin/bash
#:
#: name = "test-ddm-trio"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

source .github/buildomat/test-ddm-common.sh

#
# trio tests
#

banner "trio"
pfexec cargo test --release -p mg-tests test_trio -- --nocapture
