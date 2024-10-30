#!/bin/bash

set -o errexit
set -o pipefail

export RUST_LOG=info

args=(
    --admin-port "$(svcprop -c -p config/admin_port "${SMF_FMRI}")"
    --admin-addr "$(svcprop -c -p config/admin_host "${SMF_FMRI}")"
)

val=$(svcprop -c -p config/rack_id "${SMF_FMRI}")
if [[ "$val" != 'unknown' ]]; then
    args+=( '--rack-id' )
    args+=( "$val" )
fi

val=$(svcprop -c -p config/sled_id "${SMF_FMRI}")
if [[ "$val" != 'unknown' ]]; then
    args+=( '--sled-id' )
    args+=( "$val" )
fi

for x in $(svcprop -c -p config/dns_servers "${SMF_FMRI}"); do
    args+=( '--dns-servers' )
    args+=( "$x" )
done

if [[ -e /opt/oxide/mgd/bin/mgd ]];
then
    # mgd.tar.gz gets the binaries at /opt/oxide/mgd/bin/
    exec /opt/oxide/mgd/bin/mgd run --with-stats "${args[@]}"
elif [[ -e /opt/oxide/mgd/mgd ]];
then
    # maghemite.tar gets the binaries at /opt/oxide/mgd/
    exec /opt/oxide/mgd/mgd run --with-stats "${args[@]}"
else
    exit 1
fi
