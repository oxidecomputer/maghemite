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

banner 'launch'

cd interop
pfexec ./interop launch

banner 'test'

pwd
find ./.falcon -ls
pgrep -lf propolis-server
pfexec ./interop exec arista "which docker; compgen -c | grep docker"
pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/account.log" > ./arista.account.log
pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/messages" > ./arista.messages
pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/nginx-access.log" > ./arista.nginx-access.log
pfexec ./interop exec arista "docker exec -it ceos1 cat /var/log/nginx-error.log" > nginx-access.log
cp *.log /work/
./baseline --show-output
