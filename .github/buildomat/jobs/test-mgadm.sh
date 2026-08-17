#!/bin/bash
#:
#: name = "test-mgadm"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

set -x
set -e

source .github/buildomat/test-common.sh

pushd mgadm

cargo nextest run
