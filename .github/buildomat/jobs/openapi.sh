#!/bin/bash
#:
#: name = "openapi"
#: variety = "basic"
#: target = "helios-2.0"
#: output_rules = [
#:   "/out/*",
#: ]
#:
#: [[publish]]
#: series = "openapi"
#: name = "ddm-admin.json"
#: from_output = "/out/ddm-admin.json"
#:
#: [[publish]]
#: series = "openapi"
#: name = "ddm-admin.json.sha256.txt"
#: from_output = "/out/ddm-admin.json.sha256.txt"
#:

set -o errexit
set -o pipefail
set -o xtrace

banner copy
pfexec mkdir -p /out
pfexec chown "$UID" /out
cp ddm-openapi/ddm-admin.json /out/ddm-admin.json
digest -a sha256 /out/ddm-admin.json > /out/ddm-admin.json.sha256.txt
