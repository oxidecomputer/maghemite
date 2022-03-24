#!/bin/bash

set -o errexit
set -o pipefail

export RUST_LOG=info

args=(
    "$(svcprop -c -p config/admin_port "${SMF_FMRI}")"
    "$(svcprop -c -p config/mode "${SMF_FMRI}")"
)

val=$(svcprop -c -p config/dendrite "${SMF_FMRI}")
if [[ "$val" == true ]]; then
    args+=( '--dendrite' )
fi

val=$(svcprop -c -p config/protod "${SMF_FMRI}")
if [[ "$val" != '""' ]]; then
    args+=( '--protod-host' )
    args+=( "$val" )
fi

val=$(svcprop -c -p config/log "${SMF_FMRI}")
if [[ "$val" != '""' ]]; then
    export RUST_LOG="$val"
fi

exec /opt/oxide/mg-ddm/bin/ddm-illumos "${args[@]}"
