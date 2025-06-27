#!/bin/bash
#:
#: name = "build-interop"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = "stable"
#: access_repos = [
#:   "oxidecomputer/testbed",
#: ]
#: output_rules = [
#:   "=/work/testbed.tar.gz",
#:   "=/work/dhcp-server",
#: ]
#:

set -x
set -e

#
# Allow this program to run either under buildomat, or in a local clone:
#
if [[ $CI == true ]]; then
	WORK=/work

	pfexec pkg install protobuf git
else
	if [[ -z $WORK || ! -d $WORK ]]; then
		printf 'ERROR: set WORK when running manually\n' >&2
		exit 1
	fi
fi

cargo --version
rustc --version

banner 'clone'
mkdir -p "$WORK/ci"
git clone git@github.com:oxidecomputer/testbed.git "$WORK/ci/testbed"

banner 'build'
cd "$WORK/ci/testbed"
cargo build \
    -p interop-lab \
    -p wrangler
cargo build --tests

banner 'prep'

mkdir -p out
cp target/debug/{interop,wrangler} out/
# grab just the file ending in the hash, not the file ending in ".d"
TEST=$(find target/debug/deps -maxdepth 1 -type f -name 'baseline-*' -exec ls -t {} + | grep -v -E '.*\.d$' | head -1)
mv "$TEST" 'out/baseline'

banner 'archive'

cd "$WORK/ci"
cat <<EOF > exclude-file.txt
testbed/.git
testbed/a4x2
testbed/archive
testbed/target
EOF
tar cvzXf exclude-file.txt \
    "$WORK/testbed.tar.gz" \
    testbed

banner 'dhcp-server'

git clone https://github.com/oxidecomputer/omicron.git "$WORK/ci/omicron"
cd "$WORK/ci/omicron"
source env.sh
if [[ $CI == true ]]; then
	source .github/buildomat/ci-env.sh
	./tools/install_builder_prerequisites.sh -y
fi
cargo build -p end-to-end-tests --bin dhcp-server --release
cp target/release/dhcp-server "$WORK/"
