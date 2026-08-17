#!/bin/bash

# NOTE: This version should be in sync with the recommended version in
# .config/nextest.toml. (Maybe build an automated way to pull the recommended
# version in the future.)
NEXTEST_VERSION='0.9.97'
PLATFORM='illumos'

source .github/buildomat/common.sh

banner "install"
pfexec pkg install clang-15

cargo install cargo-nextest --version "$NEXTEST_VERSION"
