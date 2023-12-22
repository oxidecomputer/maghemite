#!/bin/bash

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
get_artifact sidecar-lite release d815d8e2b310de8a7461241d9f9f1b5c762e1e65 libsidecar_lite.so
get_artifact sidecar-lite release d815d8e2b310de8a7461241d9f9f1b5c762e1e65 scadm
get_artifact dendrite image 350fb25d724578dd2b127499edcd57981d4bbff2 dendrite-softnpu.tar.gz

pushd download
chmod +x softnpu
chmod +x scadm
rm -rf zones/dendrite
mkdir -p zones/dendrite
tar -xzf dendrite-softnpu.tar.gz -C zones/dendrite
popd

banner "install"
pkg info brand/sparse | grep -qi installed
if [[ $? != 0 ]]; then
    set -o errexit
    pfexec pkg install brand/sparse
fi

set -o errexit
set -o pipefail

banner "build"
cargo build --release --bin ddmd --bin ddmadm
