# On illumos, only mg-tests (ztest-based) needs exclusion. On other
# platforms, exclude all illumos-only crates.
build_excludes := if os() == "illumos" {
    ""
} else {
    "--exclude ddm --exclude ddmd --exclude falcon-lab --exclude lab"
}

test_excludes := build_excludes + " --exclude mg-tests"

# Build the workspace.
build:
    cargo build --workspace {{ build_excludes }}

# Run cargo test for the workspace.
test:
    cargo test --workspace {{ test_excludes }}

# Run cargo nextest for the workspace.
nextest:
    cargo nextest run --workspace {{ test_excludes }}

# Type-check all targets.
check:
    cargo check --all-targets

# Run clippy with warnings as errors.
clippy:
    cargo clippy --all-targets -- --deny warnings

# Check formatting.
fmt-check:
    cargo fmt --all --check

# Apply formatting.
fmt:
    cargo fmt --all

# Generate OpenAPI specs (requires mgd to be built first).
openapi-generate:
    cargo build --bin mgd
    cargo xtask openapi generate

# Verify OpenAPI specs are up to date.
openapi-check:
    cargo xtask openapi check

# Run all verification checks.
verify: clippy fmt-check openapi-check
