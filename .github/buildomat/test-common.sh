#!/bin/bash

# NOTE: This version should be in sync with the recommended version in
# .config/nextest.toml. (Maybe build an automated way to pull the recommended
# version in the future.)
NEXTEST_VERSION='0.9.97'
PLATFORM='illumos'

banner "install"
set +o errexit
pkg info clang-15 | grep -qi installed
if [[ $? != 0 ]]; then
    set -o errexit
    pfexec pkg install clang-15
fi
set -o errexit

cargo --version
rustc --version
cargo install cargo-nextest --version "$NEXTEST_VERSION"
