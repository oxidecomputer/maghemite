#!/bin/bash
#:
#: name = "p5p"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "/out/*.p5p",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#:   "oxidecomputer/falcon",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build
ptime -m cargo build --release --verbose -p ddmd -p ddmadm

banner p5p
pushd pkg
./build.sh

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
mv packages/repo/*.p5p /out/
