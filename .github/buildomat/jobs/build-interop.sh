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
#: ]
#:

set -x
set -e

cargo --version
rustc --version

cargo install cargo-nextest
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
