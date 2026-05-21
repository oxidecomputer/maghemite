#!/bin/bash
#:
#: name = "shellcheck"
#: variety = "basic"
#: target = "ubuntu-22.04"

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
