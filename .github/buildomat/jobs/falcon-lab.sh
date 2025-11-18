#!/bin/bash
#:
#: name = "falcon"
#: variety = "basic"
#: target = "lab-2.0-gimlet"
#: skip_clone = true
#: 
#: [dependencies.build-interop]
#: job = "build-interop"
#: 
#: [dependencies.build]
#: job = "build"
#:

set -x
set -e

banner 'zpool'

# pick the largest disk available
DISK=$(pfexec diskinfo -pH | sort -k8 -n -r | head -1 | awk '{print $2}')
export DISK
pfexec zpool create -o ashift=12 -f cpool "$DISK"
pfexec zfs create -o mountpoint=/ci cpool/ci

if [[ $(curl -s http://catacomb.eng.oxide.computer:12346/trim-me) =~ "true" ]]; then
		pfexec zpool trim cpool
		while [[ ! $(zpool status -t cpool) =~ "100%" ]]; do sleep 10; done
fi

pfexec chown "$UID" /ci
cd /ci
export FALCON_DATASET="cpool/falcon"

banner 'setup'

cp /input/build-interop/work/dhcp-server .
cp /input/build/work/release/falcon-lab .
cp /input/build/work/release/mgd .
cp /input/build/work/release/ddmd .

chmod +x dhcp-server falcon-lab mgd ddmd

mkdir -p cargo-bay
mv mgd cargo-bay/
mv ddmd cargo-bay/

export EXT_INTERFACE=${EXT_INTERFACE:-igb0}

first=$(bmat address ls -f extra -Ho first)
last=$(bmat address ls -f extra -Ho last)
gw=$(bmat address ls -f extra -Ho gateway)
server=$(ipadm show-addr "$EXT_INTERFACE"/dhcp -po ADDR | sed 's#/.*##g')
pfexec ./dhcp-server "$first" "$last" "$gw" "$server" &> /work/dhcp-server.log &

RUST_LOG=debug pfexec ./falcon-lab run \
	--dendrite-commit 0c2ab6c341bf9e3802c688961b3bc687b941a144 \
	trio-unnumbered
