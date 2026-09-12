#!/bin/bash
#:
#: name = "test-ddm-sextet"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]

source .github/buildomat/test-ddm-common.sh

#
# trio tests
#

banner "trio"
pfexec cargo test --release -p mg-tests test_external_peer_sextet -- --nocapture
