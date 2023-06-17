#!/bin/bash
#:
#: name = "test"
#: variety = "basic"
#: target = "helios-latest"
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
get_artifact softnpu image 88f5f1334364e5580fe778c44ac0746a35927351 softnpu
get_artifact sidecar-lite release 3fff53ae549ab1348b680845693e66b224bb5d2f libsidecar_lite.so
get_artifact sidecar-lite release 3fff53ae549ab1348b680845693e66b224bb5d2f scadm
get_artifact dendrite image 8065d8bca526adadf9b50b7581b7913fab28de49 dendrite-softnpu.tar.gz

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

if [[ $DOWNLOAD_ONLY -eq 1 ]]; then
    exit 0;
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
# quartet tests
#

banner quartet debug
pfexec cargo test -p mg-tests test_quartet -- --nocapture

banner quartet release
pfexec cargo test --release -p mg-tests test_quartet -- --nocapture

#
# diamond tests
#

banner diamond debug
pfexec cargo test -p mg-tests test_diamond -- --nocapture

banner diamond release
pfexec cargo test --release -p mg-tests test_diamond -- --nocapture
