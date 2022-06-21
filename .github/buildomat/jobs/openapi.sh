#!/bin/bash
#:
#: name = "openapi"
#: variety = "basic"
#: target = "helios"
#: output_rules = [
#:   "/out/*.json",
#: ]
#:
#: [[publish]]
#: series = "openapi"
#: name = "ddm-admin.json"
#: from_output = "/out/ddm-admin.json"
#:

set -o errexit
set -o pipefail
set -o xtrace

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
cp ddm-openapi/ddm-admin.json /out/ddm-admin.json
