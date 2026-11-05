#!/bin/bash
#:
#: name = "build"
#: variety = "basic"
#: target = "helios-3.0"
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

source .github/buildomat/common.sh
pfexec pkg install clang-15

banner "check"
cargo fmt -- --check
cargo clippy --all-targets -- --deny warnings
cargo xtask openapi check

banner "build"
ptime -m cargo build
ptime -m cargo build --release

for x in debug release
do
    mkdir -p /work/"${x}"
    cp target/"${x}"/ddmd /work/"${x}"/ddmd
    cp target/"${x}"/ddmadm /work/"${x}"/ddmadm
    cp target/"${x}"/mgd /work/"${x}"/mgd
    cp target/"${x}"/mgadm /work/"${x}"/mgadm
done

cp target/release/falcon-lab /work/release/falcon-lab

# The falcon job has no clone; pass it the dendrite commit mgd is built against
# and the sidecar-lite commit the ddm tests pair with it.
grep -A3 'dpd-client' Cargo.toml | sed -n 's/^rev = "\(.*\)"/\1/p' > /work/release/dendrite-commit
sed -n 's/^export SIDECAR_LITE_VERSION=//p' .github/buildomat/test-ddm-common.sh > /work/release/sidecar-lite-commit
