set unstable

# illumos-only deps (libnet, opte-ioctl, oxide-vpc) are gated behind ddm's
# `backend` feature. Disable it off-illumos so ddm/ddmd compile against stubs.
ddm_backend := if os() == "illumos" { "" } else { " --no-default-features" }

# lab/falcon-lab need libfalcon; mg-tests needs the illumos kernel (ztest).
# ddm/ddmd are always included — they compile on all platforms.
build_excludes := if os() == "illumos" { "" } else { "--exclude falcon-lab --exclude lab" }
test_excludes := build_excludes + " --exclude mg-tests"

# Package groups: mgd = mgd + mgadm, ddm = ddmd + ddm + ddmadm.
mgd_pkgs := "-p mgd -p mgadm"
ddm_pkgs := "-p ddmd -p ddm -p ddmadm" + ddm_backend
all_pkgs := "--workspace " + test_excludes

# check/clippy require --workspace with --exclude (build/test/nextest don't).
all_check := "--workspace " + build_excludes

# API crates for OpenAPI preflight builds.
mgd_api := "-p mg-api"
ddm_api := "-p ddm-api"
all_api := mgd_api + " " + ddm_api

# Select package group for test/nextest (all excludes mg-tests).
pkgs(target) := if target == "ddm" {
    ddm_pkgs
} else if target == "mgd" {
    mgd_pkgs
} else {
    all_pkgs
}

# Select package group for check/clippy (all keeps mg-tests).
check_pkgs(target) := if target == "ddm" {
    ddm_pkgs
} else if target == "mgd" {
    mgd_pkgs
} else {
    all_check
}

# Select API crate(s) for OpenAPI preflight builds.
api(target) := if target == "ddm" {
    ddm_api
} else if target == "mgd" {
    mgd_api
} else {
    all_api
}

# Build the workspace.
build *ARGS:
    cargo build --workspace {{ build_excludes }} {{ ARGS }}

# Run cargo test for a target: `all`, `mgd`, or `ddm` (default: all).
[arg('target', pattern='all|ddm|mgd')]
test target='all':
    cargo test {{ pkgs(target) }}

# Run cargo nextest for a target: `all`, `mgd`, or `ddm` (default: all).
[arg('target', pattern='all|ddm|mgd')]
nextest target='all':
    cargo nextest run {{ pkgs(target) }}

# Build a daemon binary: `mgd`, `ddm`, or `all` (default: all).
[arg('target', pattern='all|ddm|mgd')]
build-daemon target='all':
    cargo build {{ if target == "ddm" { "--bin ddmd" } else if target == "mgd" { "--bin mgd" } else { "--bin mgd --bin ddmd" } }}

# Run a daemon: `mgd` or `ddm` (default: mgd); extra args are forwarded.
# `mgd` takes a `run` subcommand, while `ddmd` runs with top-level args.
[arg('target', pattern='ddm|mgd')]
run target='mgd' *ARGS:
    cargo run --bin {{ if target == "ddm" { "ddmd" } else { "mgd" } }} -- {{ if target == "ddm" { ARGS } else { "run " + ARGS } }}

# Type-check targets for a target: `all`, `mgd`, or `ddm` (default: all).
[arg('target', pattern='all|ddm|mgd')]
check target='all':
    cargo check --all-targets {{ check_pkgs(target) }}

# Run clippy with warnings as errors for a target (default: all).
[arg('target', pattern='all|ddm|mgd')]
clippy target='all':
    cargo clippy --all-targets {{ check_pkgs(target) }} -- --deny warnings

# Check formatting.
fmt-check:
    cargo fmt --all --check

# Apply formatting.
fmt:
    cargo fmt --all

# Generate OpenAPI specs for a target (default: all).
# Preflight-builds the target's API crate(s), then runs the OpenAPI manager,
# which generates all managed specs (ddm-admin and mg-admin).
[arg('target', pattern='all|ddm|mgd')]
openapi-generate target='all':
    cargo build {{ api(target) }}
    cargo xtask openapi generate

# Verify OpenAPI specs are up to date for a target (default: all).
[arg('target', pattern='all|ddm|mgd')]
openapi-check target='all':
    cargo build {{ api(target) }}
    cargo xtask openapi check

# Run all verification checks for a target (default: all).
verify target='all': (clippy target) fmt-check (openapi-check target)
