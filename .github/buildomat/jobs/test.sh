#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/*.log",
#: ]
#: access_repos = [
#:   "oxidecomputer/dendrite",
#: ]
#:

function cleanup {
    pfexec chown -R `id -un`:`id -gn` .
}
trap cleanup EXIT

function get_artifact {
    repo=$1
    series=$2
    commit=$3
    name=$4
    url=https://buildomat.eng.oxide.computer/public/file/oxidecomputer

    mkdir -p download
    pushd download
    if [[ ! -f $name ]]; then
        curl -fOL $url/$repo/$series/$commit/$name
    fi
    popd
}

set -o xtrace

cargo --version
rustc --version

dladm
ipadm

banner "collect"
get_artifact softnpu image 64beaff129b7f63a04a53dd5ed0ec09f012f5756 softnpu
get_artifact sidecar-lite release 47c7e8e70253ed441ae25db20b2e32ee9c38e3e3 libsidecar_lite.so
get_artifact sidecar-lite release 47c7e8e70253ed441ae25db20b2e32ee9c38e3e3 scadm
get_artifact dendrite image 3ad86ab61f2ae79d877ee31351b112512b2770f5 dendrite-softnpu.tar.gz

pushd download
chmod +x softnpu
chmod +x scadm
rm -rf zones/dendrite
mkdir -p zones/dendrite
tar -xzf dendrite-softnpu.tar.gz -C zones/dendrite
popd

banner "install"
pkg info brand/sparse | grep -q installed
if [[ $? != 0 ]]; then
    set -o errexit
    pfexec pkg install brand/sparse
fi

set -o errexit
set -o pipefail

banner "test"
cargo build --bin ddmd --bin ddmadm
cargo build --release --bin ddmd --bin ddmadm

#
# trio tests
#

banner trio debug
pfexec cargo test -p mg-tests test_trio -- --nocapture

banner trio release
pfexec cargo test --release -p mg-tests test_trio -- --nocapture

#
# quartest tests
#

banner quartet debug
pfexec cargo test -p mg-tests test_quartet -- --nocapture

banner quartet release
pfexec cargo test --release -p mg-tests test_quartet -- --nocapture
