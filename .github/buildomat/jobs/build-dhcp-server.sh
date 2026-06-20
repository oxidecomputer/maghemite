#!/bin/bash
#:
#: name = "build-dhcp-server"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: skip_clone = true
#: output_rules = [
#:   "=/work/dhcp-server",
#: ]

set -x
set -e
set -o pipefail

#
# Allow this program to run either under buildomat, or in a local clone:
#
if [[ ${CI:-} == true ]]; then
	WORK=/work

	pfexec pkg install protobuf git
else
	if [[ -z ${WORK} || ! -d ${WORK} ]]; then
		printf 'ERROR: set WORK when running manually\n' >&2
		exit 1
	fi
fi

cargo --version
rustc --version

banner 'dhcp-server'

git clone https://github.com/oxidecomputer/omicron.git "${WORK}/ci/omicron"
cd "${WORK}/ci/omicron"
# shellcheck source=/dev/null
source env.sh
if [[ ${CI:-} == true ]]; then
	# shellcheck source=/dev/null
	source .github/buildomat/ci-env.sh
	./tools/install_builder_prerequisites.sh -y
fi
cargo build -p end-to-end-tests --bin dhcp-server --release
cp target/release/dhcp-server "${WORK}/"
