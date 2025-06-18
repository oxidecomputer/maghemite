#!/bin/bash
#:
#: name = "test-interop"
#: variety = "basic"
#: target = "lab-2.0-gimlet"
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

ssh() {
	if [ -z $SSH_BIN ]; then
		SSH_BIN=$(which ssh)
	fi

	$SSH_BIN -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $@
}

net_info() {
	#
	# grab command output to see what's going on from the buildomat logs
	#
	if [ -z $ARISTA_IP ]; then
		ARISTA_IF=`pfexec ./interop exec arista "ip -4 -j route show default | jq '.[0][\"dev\"]' | tr -d '\"'"`
		ARISTA_IP=`pfexec ./interop exec arista "ip -4 -br -j addr show dev $ARISTA_IF | jq '.[0][\"addr_info\"][0][\"local\"]' | tr -d '\"'"`
	fi
	ssh root@$ARISTA_IP "docker exec -t ceos1 Cli -c 'show ip interface brief | no-more'"
	ssh root@$ARISTA_IP "docker exec -t ceos1 Cli -c 'show ip bgp summary | no-more'"
	ssh root@$ARISTA_IP "docker exec -t ceos1 Cli -c 'show ip bgp | no-more'"
	ssh root@$ARISTA_IP "docker exec -t ceos1 Cli -c 'show ip route | no-more'"

	if [ -z $JUNIPER_IP ]; then
		JUNIPER_IF=`pfexec ./interop exec juniper "ip -j route show default | jq '.[0][\"dev\"]' | tr -d '\"'"`
		JUNIPER_IP=`pfexec ./interop exec juniper "ip -4 -br -j addr show dev $JUNIPER_IF | jq '.[0][\"addr_info\"][0][\"local\"]' | tr -d '\"'"`
	fi
	ssh root@$JUNIPER_IP "docker exec -t crpd1 cli -c 'show interfaces terse | no-more'"
	ssh root@$JUNIPER_IP "docker exec -t crpd1 cli -c 'show bgp summary | no-more'"
	ssh root@$JUNIPER_IP "docker exec -t crpd1 cli -c 'show route | no-more'"

	if [ -z $MGD_IP ]; then
		MGD_IF=`pfexec ./interop exec mgd "route get -inet default | grep interface | awk '{print \\$NF}'"`
		MGD_IP=`pfexec ./interop exec mgd "ipadm show-addr $MGD_IF/v4 -p -o addr | awk -F '/' '{print \\$1}'"`
	fi
	ssh root@$MGD_IP "/opt/cargo-bay/mgadm bgp status neighbors 65100"
	ssh root@$MGD_IP "/opt/cargo-bay/mgadm bgp status imported 65100"
	ssh root@$MGD_IP "/opt/cargo-bay/mgadm bgp status selected 65100"
	ssh root@$MGD_IP "/opt/cargo-bay/mgadm bgp status exported 65100"
}

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
	pfexec ls -l /ci

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
	if [ -z $ARISTA_IP ]; then
		ARISTA_IF=`pfexec ./interop exec arista "ip -4 -j route show default | jq '.[0][\"dev\"]' | tr -d '\"'"`
		ARISTA_IP=`pfexec ./interop exec arista "ip -4 -br -j addr show dev $ARISTA_IF | jq '.[0][\"addr_info\"][0][\"local\"]' | tr -d '\"'"`
	fi
	ssh root@$ARISTA_IP "cp /tmp/init.log /tmp/arista.init.log"
	ssh root@$ARISTA_IP "docker ps -a > /tmp/arista.docker-ps.log"
	ssh root@$ARISTA_IP "docker logs ceos1 > /tmp/arista.docker.logs"
	ssh root@$ARISTA_IP "docker exec -t ceos1 cat /var/log/account.log > /tmp/arista.account.log"
	ssh root@$ARISTA_IP "docker exec -t ceos1 cat /var/log/messages > /tmp/arista.messages"
	ssh root@$ARISTA_IP "docker exec -t ceos1 cat /var/log/nginx-error.log > /tmp/arista.nginx-error.log"
	ssh root@$ARISTA_IP "docker exec -t ceos1 cat /var/log/nginx-access.log > /tmp/arista.nginx-access.log"
	scp root@$ARISTA_IP:/tmp/*.log /work

	if [ -z $JUNIPER_IP ]; then
		JUNIPER_IF=`pfexec ./interop exec juniper "ip -j route show default | jq '.[0][\"dev\"]' | tr -d '\"'"`
		JUNIPER_IP=`pfexec ./interop exec juniper "ip -4 -br -j addr show dev $JUNIPER_IF | jq '.[0][\"addr_info\"][0][\"local\"]' | tr -d '\"'"`
	fi
	ssh root@$JUNIPER_IP "cp /tmp/init.log /tmp/juniper.init.log"
	ssh root@$JUNIPER_IP "docker ps -a > /tmp/juniper.docker-ps.log"
	ssh root@$JUNIPER_IP "docker logs crpd1 > /tmp/juniper.docker-logs.log"
	ssh root@$JUNIPER_IP "docker exec -t crpd1 cat /var/log/messages > /tmp/juniper-messages.log"
	ssh root@$JUNIPER_IP "docker exec -t crpd1 cat /var/log/na-grpcd > /tmp/juniper-na-grpcd.log"
	scp root@$JUNIPER_IP:/tmp/*.log /work

	# /tmp filepaths chosen in testbed/interop/src/interop.rs and testbed/interop/cargo-bay/mgd/init.sh
	if [ -z $MGD_IP ]; then
		MGD_IF=`pfexec ./interop exec mgd "route get -inet default | grep interface | awk '{print \\$NF}'"`
		MGD_IP=`pfexec ./interop exec mgd "ipadm show-addr $MGD_IF/v4 -p -o addr | awk -F '/' '{print \\$1}'"`
	fi
	ssh root@$MGD_IP "cp /tmp/init.log /tmp/mgd.init.log"
	scp root@$MGD_IP:/tmp/{mgd.init,mgd}.log /work

	net_info

	find /work -ls

	exit 1
}

trap _exit_trap EXIT

banner 'inputs'

find /input -ls

banner 'zpool'

# pick the largest disk available
export DISK=$(pfexec diskinfo -pH | sort -k8 -n -r | head -1 | awk '{print $2}')
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

banner 'status'

net_info

banner 'test'

./baseline --show-output
# XXX: NOP TO FORCE BUILDOMAT TO RUN
