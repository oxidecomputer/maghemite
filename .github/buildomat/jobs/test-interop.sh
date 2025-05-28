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

banner 'inputs'

find /input -ls

banner 'zpool'

export DISK=${DISK:-c1t1d0}
pfexec diskinfo
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

pfexec diskinfo
pfexec zfs list

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

pwd
find ./.falcon -ls
cp ./.falcon/{arista,juniper,mgd}* /work/
pgrep -lf propolis-server
pfexec ./interop exec arista "cat /tmp/init.log" > /work/arista.init.log
pfexec ./interop exec juniper "cat /tmp/init.log" > /work/juniper.init.log
pfexec ./interop exec mgd "cat /tmp/init.log" > /work/mgd.init.log
# pfexec ./interop exec arista "which docker" > /work/arista.docker.log
# pfexec ./interop exec arista "compgen -c | grep docker" > /work/arista.compgen.log
# pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/account.log" > /work/arista.account.log
# pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/messages" > /work/arista.messages
# pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/nginx-error.log" > /work/arista.nginx-error.log
# pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/nginx-access.log" > /work/arista.nginx-access.log
./baseline --show-output
