#!/bin/bash
#:
#: name = "image"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "nightly"
#: output_rules = [
#:   "/out/*",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#:   "oxidecomputer/falcon",
#: ]
#:
#: [[publish]]
#: series = "image"
#: name = "mg-ddm.tar"
#: from_output = "/out/mg-ddm.tar"
#:
#: [[publish]]
#: series = "image"
#: name = "mg-ddm.sha256.txt"
#: from_output = "/out/mg-ddm.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build
ptime -m cargo build --release --verbose -p ddmd -p ddmadm

banner image
ptime -m cargo run -p mg-package

banner contents
tar tvfz out/mg-ddm.tar

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
mv out/mg-ddm.tar /out/mg-ddm.tar
cd /out
digest -a sha256 mg-ddm.tar > mg-ddm.sha256.txt
