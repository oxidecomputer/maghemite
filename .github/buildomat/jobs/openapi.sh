#!/bin/bash
#:
#: name = "openapi"
#: variety = "basic"
#: target = "helios"
#: output_rules = [
#:   "/out/*.json",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
cp ddm-openapi/ddm-admin.json /out/ddm-admin.json
