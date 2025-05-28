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

cargo --version
rustc --version

pfexec pkg install protobuf git

banner 'clone'
pfexec mkdir /ci
pfexec chown "$UID" /ci
cd /ci
git clone https://github.com/oxidecomputer/testbed

banner 'build'
cd testbed
pwd
cargo build \
    -p interop-lab \
    -p wrangler
cargo build --tests

banner 'prep'

mkdir out
cp target/debug/{interop,wrangler} out
# grab just the file ending in the hash, not the file ending in ".d"
TEST=$(ls -t target/debug/deps/baseline-* | egrep -v '.*\.d$' | head -1)
mv $TEST out/baseline
cd ..

banner 'archive'

cat <<EOF > exclude-file.txt
testbed/.git
testbed/a4x2
testbed/archive
testbed/target
EOF
tar cvzXf exclude-file.txt \
    /work/testbed.tar.gz \
    testbed

banner 'dhcp-server'

git clone https://github.com/oxidecomputer/omicron.git
cd omicron
source env.sh
source .github/buildomat/ci-env.sh
# try just using builder prereqs
# pfexec ./tools/install_prerequisites.sh
pfexec ./tools/install_builder_prerequisites.sh -y
stat target
stat target/{debug,release}
pfexec mkdir -p target/release
pfexec chown "$UID" /target
pfexec chown "$UID" /target/release
stat target
stat target/{debug,release}
cargo build -p end-to-end-tests --bin dhcp-server --release
cp target/release/dhcp-server /work/
