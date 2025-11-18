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
#: series = "release"
#: name = "falcon-lab"
#: from_output = "/work/release/falcon-lab"
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
#: [[publish]]
#: series = "debug"
#: name = "mgd"
#: from_output = "/work/debug/mgd"
#:
#: [[publish]]
#: series = "debug"
#: name = "mgadm"
#: from_output = "/work/debug/mgadm"
#:
#: [[publish]]
#: series = "release"
#: name = "mgd"
#: from_output = "/work/release/mgd"
#:
#: [[publish]]
#: series = "release"
#: name = "mgadm"
#: from_output = "/work/release/mgadm"
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
cargo xtask openapi check

banner "build"
ptime -m cargo build
ptime -m cargo build --release

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/ddmd /work/$x/ddmd
    cp target/$x/ddmadm /work/$x/ddmadm
    cp target/$x/mgd /work/$x/mgd
    cp target/$x/mgadm /work/$x/mgadm
done

cp target/release/falcon-lab /work/release/falcon-lab
