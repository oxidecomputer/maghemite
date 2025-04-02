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
get_artifact softnpu image b016b192ed6bb7e2ebee024f48263f627bade5a4 softnpu
get_artifact sidecar-lite release 117c38829e4c3129583a92e27cb55d318da1ce6e libsidecar_lite.so
get_artifact sidecar-lite release 117c38829e4c3129583a92e27cb55d318da1ce6e scadm
get_artifact dendrite image 0dcd325bef5445edf9ff89526e7da0be603ee2c7 dendrite-softnpu.tar.gz

pushd download
chmod +x softnpu
chmod +x scadm
rm -rf zones/dendrite
mkdir -p zones/dendrite
tar -xzf dendrite-softnpu.tar.gz -C zones/dendrite
sed -i  "s#<service_fmri value='svc:/oxide/zone-network-setup:default' />##g" \
    zones/dendrite/root/var/svc/manifest/site/dendrite/manifest.xml 
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
