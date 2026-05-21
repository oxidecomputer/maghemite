#!/bin/bash
#:
#: name = "linux"
#: variety = "basic"
#: target = "ubuntu-24.04"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#:
#: [[publish]]
#: series = "linux"
#: name = "mgd"
#: from_output = "/work/release/mgd"
#:
#: [[publish]]
#: series = "linux"
#: name = "mgd.sha256.txt"
#: from_output = "/work/release/mgd.sha256.txt"
#:
#: [[publish]]
#: series = "linux"
#: name = "mgadm"
#: from_output = "/work/release/mgdadm"
#:
#: [[publish]]
#: series = "linux"
#: name = "mgadm.sha256.txt"
#: from_output = "/work/release/mgadm.sha256.txt"
#:
#: [[publish]]
#: series = "linux"
#: name = "ddmd"
#: from_output = "/work/release/ddmd"
#:
#: [[publish]]
#: series = "linux"
#: name = "ddmd.sha256.txt"
#: from_output = "/work/release/ddmd.sha256.txt"
#:
#: [[publish]]
#: series = "linux"
#: name = "ddmadm"
#: from_output = "/work/release/ddmadm"
#:
#: [[publish]]
#: series = "linux"
#: name = "ddmadm.sha256.txt"
#: from_output = "/work/release/ddmadm.sha256.txt"

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

function digest {
    shasum -a 256 "$1" | awk -F ' ' '{print $1}'
}

banner "packages"
sudo apt update -y
sudo apt install -y pkg-config libssl-dev

mkdir -p /work/debug
mkdir -p /work/release

banner "mgd"
pushd mgd
cargo build --bin mgd --no-default-features
cargo build --bin mgd --no-default-features --release
popd
cp target/debug/mgd /work/debug
cp target/release/mgd /work/release
digest /work/release/mgd > /work/release/mgd.sha256.txt

banner "mgadm"
pushd mgadm
cargo build --bin mgadm
cargo build --bin mgadm --release
popd
cp target/debug/mgadm /work/debug
cp target/release/mgadm /work/release
digest /work/release/mgadm > /work/release/mgadm.sha256.txt

banner "ddmd"
pushd ddmd
cargo build --bin ddmd --no-default-features
cargo build --bin ddmd --no-default-features --release
popd
cp target/debug/ddmd /work/debug
cp target/release/ddmd /work/release
digest /work/release/ddmd > /work/release/ddmd.sha256.txt

banner "ddmadm"
pushd ddmadm
cargo build --bin ddmadm
cargo build --bin ddmadm --release
popd
cp target/debug/ddmadm /work/debug
cp target/release/ddmadm /work/release
digest /work/release/ddmadm > /work/release/ddmadm.sha256.txt
