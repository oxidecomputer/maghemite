#!/bin/bash

export PUBLISHER=helios-netdev
export COMMIT_COUNT=`git rev-list --count HEAD`
export REPO=packages/repo

set -e

./clean.sh

# create the proto area
mkdir -p proto/lib/svc/manifest/system
mkdir -p proto/opt/oxide/maghemite/bin
cp ../smf/ddm/manifest.xml proto/lib/svc/manifest/system/mg-ddm.xml
cp ../smf/ddm_method_script.sh proto/opt/oxide/maghemite/bin/
cp ../target/release/ddmd proto/opt/oxide/maghemite/bin/
cp ../target/release/ddmadm proto/opt/oxide/maghemite/bin/

# create the package
sed -e "s/%PUBLISHER%/$PUBLISHER/g" \
    -e "s/%COMMIT_COUNT%/$COMMIT_COUNT/g" \
    maghemite.template.p5m | pkgmogrify -v -O maghemite.base.p5m

pkgdepend generate -d proto maghemite.base.p5m > maghemite.generate.p5m

mkdir -p packages
pkgdepend resolve -d packages -s resolve.p5m maghemite.generate.p5m

cat maghemite.base.p5m packages/maghemite.generate.p5m.resolve.p5m > maghemite.final.p5m

pkgrepo create $REPO
pkgrepo add-publisher -s $REPO $PUBLISHER

pkgsend publish -d proto -s $REPO maghemite.final.p5m
pkgrecv -a -d packages/repo/maghemite-0.1.$COMMIT_COUNT.p5p -s $REPO -v -m latest '*'
