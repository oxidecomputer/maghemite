#!/bin/bash
#:
#: name = "build"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#:
#: [[publish]]
#: series = "release"
#: name = "ddmd"
#: from_output = "/work/release/ddmd"
#:
#: [[publish]]
#: series = "release"
#: name = "ddmadm"
#: from_output = "/work/release/ddmadm"
#:
#: [[publish]]
#: series = "debug"
#: name = "ddmd"
#: from_output = "/work/debug/ddmd"
#:
#: [[publish]]
#: series = "debug"
#: name = "ddmadm"
#: from_output = "/work/debug/ddmadm"
#:

set -o errexit
set -o pipefail
set -o xtrace

pfexec pkg install clang-15
cargo --version
rustc --version

banner "check"
cargo fmt -- --check
cargo clippy --all-targets -- --deny warnings

banner "build"
ptime -m cargo build
ptime -m cargo build --release

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/ddmd /work/$x/ddmd
    cp target/$x/ddmadm /work/$x/ddmadm
done
