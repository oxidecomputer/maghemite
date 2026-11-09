#!/bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Copyright Oxide Computer Company

set -o errexit
set -o pipefail
set -o xtrace

# We use `--netrc` in these calls in order to use the GitHub token Buildomat
# provides us. This is not strictly necessary for all APIs we use, _except_ the
# one to download artifacts. But using it for all calls keeps us from hitting
# rate limits!

API_BASE="https://api.github.com/repos/$GITHUB_REPOSITORY"

# Buildomat creates at most one check suite per commit per repository, but
# GitHub Actions will generally make several. We need to choose which run we
# care about, ideally picking the one most closely related to this Buildomat
# check suite. We first look for the most recently-created "push" run, but if
# none are found we fall back to the most recently-created "pull_request" run.
#
# We check 10 times with 30 second pauses in between; if we don't have a check
# run within about five minutes it'll probably never show up.
for attempt in {1..10}; do
    runs=$(curl -sSfL --netrc "$API_BASE/actions/runs?head_sha=$GITHUB_SHA" \
        | jq -r --arg name "$1" '
            .workflow_runs
            | sort_by(.created_at) | reverse
            | .[] | select(.name == $name)
            | {id: .id, event: .event}
        ')
    for event in push pull_request; do
        run_id=$(jq -r --arg event "$event" 'select(.event == $event) | .id' <<<"$runs" | head -n 1)
        [[ -n "$run_id" ]] && break 2
    done
    sleep 30
done
if [[ -z "$run_id" ]]; then
    echo >&2 "no check run found"
    exit 1
fi

# Wait for the run to complete.
until [[ $(curl -sSfL --netrc "$API_BASE/actions/runs/$run_id" | jq -r .status) == completed ]]; do
    sleep 60
done

# Get information about artifacts and download them.
artifacts=$(curl -sSfL --netrc "$API_BASE/actions/runs/$run_id/artifacts" \
    | jq -r '.artifacts[] | {id: .id, name: .name}')
for artifact_id in $(jq -r '.id' <<<"$artifacts"); do
    artifact_name=$(jq -r --argjson id "$artifact_id" 'select(.id == $id) | .name' <<<"$artifacts")
    # Artifact names are not allowed to contain special filesystem characters:
    # https://github.com/actions/upload-artifact/issues/22
    curl -sSfL --netrc -o "$artifact_name.zip" \
        "$API_BASE/actions/artifacts/$artifact_id/zip"
done
