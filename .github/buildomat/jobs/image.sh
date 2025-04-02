#!/bin/bash
#:
#: name = "image"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "image"
#: name = "mg-ddm-gz.tar"
#: from_output = "/out/mg-ddm-gz.tar"
#:
#: [[publish]]
#: series = "image"
#: name = "mg-ddm-gz.sha256.txt"
#: from_output = "/out/mg-ddm-gz.sha256.txt"
#:
#: [[publish]]
#: series = "image"
#: name = "mg-ddm.tar.gz"
#: from_output = "/out/mg-ddm.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "mg-ddm.sha256.txt"
#: from_output = "/out/mg-ddm.sha256.txt"
#
#: [[publish]]
#: series = "image"
#: name = "mgd.tar.gz"
#: from_output = "/out/mgd.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "mgd.sha256.txt"
#: from_output = "/out/mgd.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build
ptime -m cargo build --release --verbose -p ddmd -p ddmadm -p mgd -p mgadm

banner image
ptime -m cargo run -p mg-package

banner mg-ddm-gz contents
tar tvfz out/mg-ddm-gz.tar

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
mv out/mg-ddm-gz.tar /out/mg-ddm-gz.tar
mv out/mg-ddm.tar.gz /out/mg-ddm.tar.gz
mv out/mgd.tar.gz /out/mgd.tar.gz

banner checksum
cd /out
digest -a sha256 mg-ddm-gz.tar > mg-ddm-gz.sha256.txt
digest -a sha256 mg-ddm.tar.gz > mg-ddm.sha256.txt
digest -a sha256 mgd.tar.gz > mgd.sha256.txt

