#!/bin/bash
#:
#: name = "test-ddm-dual"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]

source .github/buildomat/test-ddm-common.sh

#
# dual sidecar tests
#

banner "dual"
pfexec cargo test --release -p mg-tests test_dual_sidecar -- --nocapture
