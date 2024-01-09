#!/bin/bash

set -o errexit
set -o pipefail

export RUST_LOG=info

args=(
    --admin-port "$(svcprop -c -p config/admin_port "${SMF_FMRI}")"
    --admin-addr "$(svcprop -c -p config/admin_host "${SMF_FMRI}")"
    --tep "$(svcprop -c -p config/tep "${SMF_FMRI}")"
)

if [[ -e /opt/oxide/mgd/bin/mgd ]];
then
    # mgd.tar.gz gets the binaries at /opt/oxide/mgd/bin/
    exec /opt/oxide/mgd/bin/mgd run "${args[@]}"
elif [[ -e /opt/oxide/mgd/mgd ]];
then
    # maghemite.tar gets the binaries at /opt/oxide/mgd/
    exec /opt/oxide/mgd/mgd run "${args[@]}"
else
    exit 1
fi

