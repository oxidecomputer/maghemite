#!/bin/bash
#:
#: name = "mg-p5p"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "=/out/mg.p5p",
#:   "=/out/mg.p5p.sha256",
#: ]
#:
#: access_repos = [
#:   "oxidecomputer/dendrite",
#:   "oxidecomputer/falcon",
#: ]
#:
#: [[publish]]
#: series = "repo"
#: name = "mg.p5p"
#: from_output = "/out/mg.p5p"
#:
#: [[publish]]
#: series = "repo"
#: name = "mg.p5p.sha256"
#: from_output = "/out/mg.p5p.sha256"
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
PKG_NAME="/out/mg.p5p"
mv packages/repo/*.p5p "$PKG_NAME"
sha256sum "$PKG_NAME" > "$PKG_NAME.sha256"
