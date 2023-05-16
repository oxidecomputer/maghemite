#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

function cleanup {
    pfexec chown -R `id -un`:`id -gn` .
}
trap cleanup EXIT

set -o xtrace

cargo --version
rustc --version

dladm
ipadm

banner "install"
pkg info brand/sparse | grep -q installed
if [[ $? != 0 ]]; then
    set -o errexit
    pfexec pkg install brand/sparse
fi

set -o errexit
set -o pipefail

banner "test"
cargo build --bin ddmd --bin ddmadm
pfexec cargo test -p mg-tests test_trio -- --nocapture
