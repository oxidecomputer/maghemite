#!/bin/bash
#:
#: name = "test-ndp"
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

cargo nextest run -p ndp -p unnumbered
