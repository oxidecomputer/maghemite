#!/bin/bash
#:
#: name = "falcon"
#: variety = "basic"
#: target = "lab-3.0-gimlet"
#: skip_clone = true
#: output_rules = [
#:   "/work/*",
#: ]
#:
#: [dependencies.build-interop]
#: job = "build-interop"
#:
#: [dependencies.build]
#: job = "build"
#:

set -x
set -e
set -o pipefail

banner 'zpool'

# pick the largest disk available
DISK=$(pfexec diskinfo -pH | sort -k8 -n -r | head -1 | awk '{print $2}')
export DISK
pfexec zpool create -o ashift=12 -f cpool "${DISK}"
pfexec zfs create -o mountpoint=/ci cpool/ci

trim_response=$(curl -s http://catacomb.eng.oxide.computer:12346/trim-me)
if [[ ${trim_response} =~ "true" ]]; then
		pfexec zpool trim cpool
		while true; do
			trim_status=$(zpool status -t cpool)
			[[ ${trim_status} =~ "100%" ]] && break
			sleep 10
		done
fi

pfexec chown "${UID}" /ci
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

# Juniper/cRPD images require a runtime license. Fetch it on the CI runner,
# which has catacomb access, and pass it to the guest by file via cargo-bay.
# The license contents must never be printed or committed.
curl -sSfL --retry 10 --retry-all-errors \
	-o cargo-bay/falcon-juniper-license.key \
	http://catacomb.eng.oxide.computer:12346/falcon/jl
chmod 0600 cargo-bay/falcon-juniper-license.key

export EXT_INTERFACE=${EXT_INTERFACE:-igb0}

first=$(bmat address ls -f extra -Ho first)
last=$(bmat address ls -f extra -Ho last)
gw=$(bmat address ls -f extra -Ho gateway)
server=$(ipadm show-addr "${EXT_INTERFACE}"/dhcp -po ADDR | sed 's#/.*##g')
pfexec ./dhcp-server "${first}" "${last}" "${gw}" "${server}" &> /work/dhcp-server.log &

RUST_LOG=debug pfexec ./falcon-lab run \
	mgd-unnumbered

RUST_LOG=debug pfexec ./falcon-lab run \
	quartet-unnumbered

RUST_LOG=debug pfexec ./falcon-lab run \
	quartet-bfd-static-routing
