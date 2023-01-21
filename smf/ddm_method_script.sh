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

for x in $(svcprop -c -p config/interfaces "${SMF_FMRI}"); do
    args+=( '-a' )
    args+=( "$x" )
done

exec /opt/oxide/mg-ddm/ddmd "${args[@]}"
