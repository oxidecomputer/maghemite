#!/bin/bash
#:
#: name = "test-bfd"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#:   "/tmp/*.db",
#: ]
#:

set -o xtrace
set -o errexit
set -o pipefail

source .github/buildomat/test-common.sh
banner bfd
cargo nextest run -p bfd --nocapture
