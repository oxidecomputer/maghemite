#!/bin/bash

# Install nextest from the prebuilt binaries published by the nextest project
# rather than building from source via `cargo install`. `cargo install`
# resolves dependencies fresh from crates.io and an updated transitive dep can
# break CI with no change on our side. Prebuilt binaries avoid that entirely.
# NOTE: This version should be in sync with the recommended version in
# .config/nextest.toml. (Maybe build an automated way to pull the recommended
# version in the future.)
NEXTEST_VERSION='0.9.97'

source .github/buildomat/common.sh

banner "install"
pfexec pkg install clang-15

# Derive the platform from the host, since jobs sourcing this script run on
# both illumos and Linux runners. This mirrors omicron's
# .github/buildomat/build-and-test.sh.
nextest_host_os="$(uname -s)"
case "${nextest_host_os}" in
	SunOS) nextest_platform='illumos' ;;
	Linux) nextest_platform='linux' ;;
	*)
		echo "error: no prebuilt nextest platform for ${nextest_host_os}" >&2
		exit 1
		;;
esac
nextest_url="https://get.nexte.st/${NEXTEST_VERSION}/${nextest_platform}"

nextest_tmp="$(mktemp -d)"
trap 'rm -rf "${nextest_tmp}"' EXIT
nextest_tar="${nextest_tmp}/nextest.tar.gz"

# Download to a file rather than piping into tar so that a failed download
# can't be masked by tar's success.
curl -sSfL --retry 10 -o "${nextest_tar}" "${nextest_url}"

mkdir -p "${CARGO_HOME:-${HOME}/.cargo}/bin"
tar -xzf "${nextest_tar}" -C "${CARGO_HOME:-${HOME}/.cargo}/bin"
