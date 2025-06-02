#!/bin/bash
#:
#: name = "test-interop"
#: variety = "basic"
#: target = "lab-2.0-opte"
#: skip_clone = true
#: output_rules = [
#:   "/work/*",
#: ]
#:
#: [dependencies.build-interop]
#: job = "build-interop"
#:
#: [dependencies.image]
#: job = "image"
#:

set -x
set -e

_exit_trap() {
	local status=$?
	[[ $status -eq 0 ]] && exit 0

	set +o errexit

	banner 'debug'

	#
	# collect general info about runner
	#
	pfexec df -h
	pfexec diskinfo
	pfexec zfs list
	pfexec zpool list
	pfexec stat /ci

	#
	# collect falcon info
	#
	find /ci/testbed/interop/.falcon -ls
	cp /ci/testbed/interop/.falcon/{arista,juniper,mgd}* /work/

	#
	# check if propolis is running
	#
	pgrep -lf propolis-server

	#
	# grab platform-specific logs
	#
	# arista
	pfexec ./interop exec arista "cat /tmp/init.log" > /work/arista.init.log
	pfexec ./interop exec arista "docker ps -a"
	pfexec ./interop exec arista "docker logs ceos1" > /work/arista.docker.logs
	pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/account.log" > /work/arista.account.log
	pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/messages" > /work/arista.messages
	pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/nginx-error.log" > /work/arista.nginx-error.log
	pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/nginx-access.log" > /work/arista.nginx-access.log
	# juniper
	pfexec ./interop exec juniper "cat /tmp/init.log" > /work/juniper.init.log
	pfexec ./interop exec juniper "docker ps -a"
	pfexec ./interop exec juniper "docker logs crpd1" > /work/juniper.docker.logs
	pfexec ./interop exec juniper "docker exec -it crpd1 cat /var/log/messages" > /work/juniper.messages
	pfexec ./interop exec juniper "docker exec -it crpd1 cat /var/log/na-grpcd" > /work/juniper.na-grpcd
	# maghemite
	# /tmp filepaths chosen in testbed/interop/src/interop.rs and testbed/interop/cargo-bay/mgd/init.sh
	pfexec ./interop exec mgd "cat /tmp/init.log" > /work/mgd.init.log
	pfexec ./interop exec mgd "cat /tmp/mgd.log" > /work/mgd.log

	exit 1
}

trap _exit_trap EXIT

banner 'inputs'

find /input -ls

banner 'zpool'

export DISK=${DISK:-c1t1d0}
pfexec zpool create -o ashift=12 -f cpool $DISK
pfexec zfs create -o mountpoint=/ci cpool/ci

if [[ $(curl -s http://catacomb.eng.oxide.computer:12346/trim-me) =~ "true" ]]; then
		pfexec zpool trim cpool
		while [[ ! $(zpool status -t cpool) =~ "100%" ]]; do sleep 10; done
fi

pfexec chown "$UID" /ci
cd /ci
export FALCON_DATASET="cpool/falcon"

banner 'setup'

tar xvfz /input/build-interop/work/testbed.tar.gz

mkdir -p image/mgd
(cd image/mgd && tar xvfz /input/image/out/mgd.tar.gz)
for bin in mgadm mgd; do
	mv "image/mgd/root/opt/oxide/mgd/bin/$bin" \
	    "testbed/interop/cargo-bay/mgd/$bin"
done
cd testbed
mkdir -p target/debug
mv out/{interop,wrangler} target/debug
mv out/baseline interop

banner 'dhcp-server'

export EXT_INTERFACE=${EXT_INTERFACE:-igb0}

cp /input/build-interop/work/dhcp-server .
chmod +x dhcp-server
first=`bmat address ls -f extra -Ho first`
last=`bmat address ls -f extra -Ho last`
gw=`bmat address ls -f extra -Ho gateway`
server=`ipadm show-addr $EXT_INTERFACE/dhcp -po ADDR | sed 's#/.*##g'`
pfexec ./dhcp-server $first $last $gw $server &> /work/dhcp-server.log &

banner 'launch'

cd interop
pfexec ./interop launch

banner 'test'

./baseline --show-output
