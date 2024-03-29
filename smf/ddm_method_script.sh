#!/bin/bash

set -o errexit
set -o pipefail

export RUST_LOG=info

args=(
    --admin-port "$(svcprop -c -p config/admin_port "${SMF_FMRI}")"
    --admin-addr "$(svcprop -c -p config/admin_host "${SMF_FMRI}")"
    --kind "$(svcprop -c -p config/mode "${SMF_FMRI}")"
)


val=$(svcprop -c -p config/dendrite "${SMF_FMRI}")
if [[ "$val" == true ]]; then
    args+=( '--dendrite' )
fi

val=$(svcprop -c -p config/dpd_host "${SMF_FMRI}")
if [[ "$val" != '""' ]]; then
    args+=( '--dpd-host' )
    args+=( "$val" )
fi

val=$(svcprop -c -p config/dpd_port "${SMF_FMRI}")
if [[ "$val" != '""' ]]; then
    args+=( '--dpd-port' )
    args+=( "$val" )
fi

val=$(svcprop -c -p config/log "${SMF_FMRI}")
if [[ "$val" != '""' ]]; then
    export RUST_LOG="$val"
fi

val=$(svcprop -c -p config/rack_uuid "${SMF_FMRI}")
if [[ "$val" != 'unknown' ]]; then
    args+=( '--rack-uuid' )
    args+=( "$val" )
fi

val=$(svcprop -c -p config/sled_uuid "${SMF_FMRI}")
if [[ "$val" != 'unknown' ]]; then
    args+=( '--sled-uuid' )
    args+=( "$val" )
fi

for x in $(svcprop -c -p config/interfaces "${SMF_FMRI}"); do
    args+=( '-a' )
    args+=( "$x" )
done

for x in $(svcprop -c -p config/dns_servers "${SMF_FMRI}"); do
    args+=( '--dns-servers' )
    args+=( "$x" )
done

if [[ -e /opt/oxide/mg-ddm/bin/ddmd ]];
then
    # mg-ddm.tar.gz gets the binaries at /opt/oxide/mg-ddm/bin/
    exec /opt/oxide/mg-ddm/bin/ddmd --with-stats "${args[@]}"
elif [[ -e /opt/oxide/mg-ddm/ddmd ]];
then
    # maghemite.tar gets the binaries at /opt/oxide/mg-ddm/
    exec /opt/oxide/mg-ddm/ddmd --with-stats "${args[@]}"
else
    exit 1
fi

