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
#: name = "maghemite.tar.gz"
#: from_output = "/out/maghemite.tar.gz"
#:
#: [[publish]]
#: series = "image"
#: name = "maghemite.sha256.txt"
#: from_output = "/out/maghemite.sha256.txt"
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
tar tvfz out/maghemite.tar.gz

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
mv out/maghemite.tar.gz /out/maghemite.tar.gz
cd /out
digest -a sha256 maghemite.tar.gz > maghemite.sha256.txt
