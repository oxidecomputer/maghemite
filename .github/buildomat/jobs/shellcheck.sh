#!/bin/bash
#:
#: name = "linux"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#:

banner "packages"
sudo apt update -y
sudo apt install -y shellcheck

banner "shellcheck"
failed=0
for script in .github/buildomat/jobs/*.sh; do
    if ! shellcheck -x "$script"; then
        echo "$script failed shellcheck" >&2
        failed=1
    fi
done
(( failed == 0 )) || exit 1
