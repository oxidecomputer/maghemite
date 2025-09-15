#!/bin/bash
#:
#: name = "mg-p5p"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "=/out/mg.p5p",
#:   "=/out/mg.p5p.sha256",
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

pfexec pkg install clang-15
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
