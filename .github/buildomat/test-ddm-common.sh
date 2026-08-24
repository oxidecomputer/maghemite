#!/bin/bash

source .github/buildomat/common.sh

export MAGHEMITE_VERSION=`git rev-parse HEAD`
export SOFTNPU_VERSION=284c6830722548714128e63ea04bcca78ee27154
export SIDECAR_LITE_VERSION=461cbe1926b93b20c2f43ad5cd9007b193db61a6
export DENDRITE_VERSION=3d49b1314dc111323052ffe4b5b7ec442d9d0f3d

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

dladm
ipadm

banner "collect"

get_artifact softnpu image $SOFTNPU_VERSION softnpu
get_artifact sidecar-lite release $SIDECAR_LITE_VERSION libsidecar_lite.so
get_artifact sidecar-lite release $SIDECAR_LITE_VERSION scadm
get_artifact dendrite image $DENDRITE_VERSION dendrite-softnpu.tar.gz
get_artifact maghemite release $MAGHEMITE_VERSION ddm
get_artifact maghemite release $MAGHEMITE_VERSION ddmadm

pushd download
chmod +x softnpu
chmod +x scadm
chmod +x ddmadm
chmod +x ddmd
mv ddmadm ddmadm-v2
mv ddmd ddmd-v2
rm -rf zones/dendrite
mkdir -p zones/dendrite
tar -xzf dendrite-softnpu.tar.gz -C zones/dendrite
sed -i  "s#<service_fmri value='svc:/oxide/zone-network-setup:default' />##g" \
    zones/dendrite/root/var/svc/manifest/site/dendrite/manifest.xml
sed -i  "s#<service_fmri value='svc:/oxide/.*setup:default' />##g" \
    zones/dendrite/root/var/svc/manifest/site/tfport/manifest.xml
popd

banner "install"
for p in clang-15 pkg-config brand/omicron1 brand/omicron1/tools ; do
    pfexec pkg install $p
done

pfexec svcadm enable baseline
retry=0
while [[ $(svcs -Hostate baseline || true) != online ]]; do
    if [[ $retry -gt 300 ]]; then
        echo "baseline service did not come online";
        exit 1;
    fi
    sleep 1;
    retry=$((retry + 1))
done
    
set -o errexit
set -o pipefail

banner "build"
cargo build --release --bin ddmd --bin ddmadm
