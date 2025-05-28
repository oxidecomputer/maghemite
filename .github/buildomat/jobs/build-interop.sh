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
	top=$PWD
	WORK=/work

	pfexec pkg install protobuf git cmake
else
	if [[ -z $WORK || ! -d $WORK ]]; then
		printf 'ERROR: set WORK when running manually\n' >&2
		exit 1
	fi

	#
	# Be resilient against someone running this while not in the repository
	# root directory:
	#
	top=$(cd "$(dirname "$0")"/../../.. && pwd)
fi

cargo --version
rustc --version

banner 'clone'
mkdir "$top/ci"
git clone https://github.com/oxidecomputer/testbed "$top/ci/testbed"

banner 'build'
cd "$top/ci/testbed"
cargo build \
    -p interop-lab \
    -p wrangler
cargo build --tests

banner 'prep'

mkdir out
cp target/debug/{interop,wrangler} out/
# grab just the file ending in the hash, not the file ending in ".d"
TEST=$(ls -t target/debug/deps/baseline-* | egrep -v '.*\.d$' | head -1)
mv "$TEST" 'out/baseline'

banner 'archive'

cd "$top/ci"
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

git clone https://github.com/oxidecomputer/omicron.git "$top/ci/omicron"
cd "$top/ci/omicron"
source env.sh
if [[ $CI == true ]]; then
	source .github/buildomat/ci-env.sh
	# try just using builder prereqs
	# ./tools/install_prerequisites.sh
	./tools/install_builder_prerequisites.sh -y
fi
cargo build -p end-to-end-tests --bin dhcp-server --release
cp target/release/dhcp-server "$WORK/"
