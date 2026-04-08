# Maghemite Developer Guide

A suite of routing protocol implementations in Rust for
[Oxide Computer Company](https://oxide.computer)'s rack architecture.
Implements upper-half routing protocols (BGP, DDM, BFD, static) with
support for illumos/Helios and Dendrite/Sidecar data planes.

## Tech Stack

- **Language**: Rust (version pinned in `rust-toolchain.toml`)
- **Async runtime**: Tokio via `oxide_tokio_rt::run` (clippy
  disallows `#[tokio::main]`)
- **HTTP API framework**: Dropshot (server) + Progenitor (client
  generation from OpenAPI)
- **Logging**: slog (structured, bunyan JSON for daemons)
- **Persistence**: sled key-value store (RIB database)
- **Policy engine**: Rhai scripting (BGP policies)
- **Metrics**: Oximeter integration
- **Formatting**: `rustfmt.toml` — edition 2024, max_width 80

## Workspace Structure

### Daemons
- **`mgd`** — Main external routing daemon. Manages BGP, BFD,
  static routing, and mg-lower. Admin API on `[::]:4676`, oximeter
  on `4677`. BGP listens on TCP 179.
- **`ddmd`** — DDM (Delay Driven Multipath) underlay routing daemon.
  Admin API on `[::]:8000`, exchange protocol on TCP `0xdddd`
  (57053).

### CLI Tools
- **`mgadm`** — Admin CLI for mgd. Subcommands: `bgp`, `static`,
  `bfd`, `rib`, `ndp`.
- **`ddmadm`** — Admin CLI for ddmd. Commands: get-peers,
  get-prefixes, advertise/withdraw, tunnel endpoints.

### Protocol Libraries
- **`bgp`** — BGP-4 (RFC 4271) + MP-BGP (IPv4/IPv6 unicast) + BGP
  unnumbered. Single-FSM-per-peer design. ~31K lines, largest
  component. Key files: `session.rs` (FSM), `messages.rs`
  (protocol), `router.rs` (management), `policy.rs` (Rhai policies),
  `unnumbered.rs` (link-local).
- **`bfd`** — Bidirectional Forwarding Detection. Per-session state
  machines, active/passive modes.
- **`ddm`** — DDM state machine per interface. Discovery via
  multicast, exchange via path-vector routing.
- **`ndp`** — Neighbor Discovery Protocol for BGP unnumbered peer
  discovery.

### Data & Routing
- **`rdb`** — Routing Information Base shared by BGP, BFD, static,
  DDM. Separate in/loc RIBs for IPv4/IPv6. Bestpath algorithm:
  shutdown filter -> RIB priority -> local_pref -> AS path length ->
  multi-exit discriminator (MED). Equal-cost multipath (ECMP) support.
  Persistent via sled at `/var/run/rdb`.
- **`rdb-types`** — Shared types for the RIB.
- **`mg-lower`** — Syncs RIB to data plane (Dendrite). Watches RIB
  for changes, full sync on startup + incremental updates. Platform
  traits: `Dpd`, `Ddm`, `SwitchZone`.
- **`mg-common`** — Shared utilities: CLI styling, logging,
  networking, stats, SMF, threading. Macros: `lock!`, `read_lock!`,
  `write_lock!`, `println_nopipe!`.

### API Layer
- **`mg-api`** — Dropshot API trait for mgd. Versioned API (see
  [API Type Versioning](#api-type-versioning)).
- **`ddm-api`** — Dropshot API trait for ddmd.
- **`mg-admin-client`** — Progenitor-generated Rust client for mgd.
- **`ddm-admin-client`** — Progenitor-generated Rust client for
  ddmd.
- **`dropshot-apis`** — OpenAPI doc management binary. Run via
  `cargo xtask openapi`.
- **`openapi/`** — OpenAPI specs for both APIs.

### Testing & Labs
- **`tests/`** — Integration tests using `ztest` (illumos
  zone-based). DDM multi-zone topologies.
- **`bgp/src/test.rs`** — BGP unit/integration tests. Uses loopback
  IPs for TCP, channels for unit tests.
- **`clab/`** — Containerlab configs with FRRouting peers.
- **`interop-lab/`** — Docker-based multi-vendor BGP testing.
- **`falcon-lab/`** — Libfalcon-based rack simulation testing.
- **`lab/`** — Solo/duo/trio/quartet test binaries.

### Build & Packaging
- **`xtask/`** — Cargo xtask for workspace tasks (currently: OpenAPI
  management).
- **`package/`** — IPS packaging for illumos (`.p5p` archives).
- **`smf/`** — Service Management Facility manifests and method
  scripts for ddmd and mgd.
- **`pkg/`** — Additional packaging resources.
- **`.github/buildomat/`** — CI jobs: build, test-bgp, test-bfd,
  test-ddm-trio/quartet, test-interop. Targets Helios 2.0.

### Other
- **`util/`** — General utilities.
- **`mg-ddm-verify`** — DDM verification tool.
- **`docs/`** — Architecture and developer docs.

## Justfile

Common workflows are available as `just` recipes. The justfile
automatically excludes illumos-only crates (`ddm`, `ddmd`,
`falcon-lab`, `lab`) on non-illumos platforms. Run `just --list`
to see all available recipes.

## Building

The build has ordering constraints — OpenAPI client generation
depends on the mgd binary:

```bash
# 1. Build mgd first
cargo build --bin mgd

# 2. Generate OpenAPI specs (requires mgd binary)
cargo xtask openapi generate

# 3. Build mgadm (depends on generated OpenAPI client)
cargo build --bin mgadm
```

## Testing

`cargo nextest` is preferred over `cargo test`.

On macOS, several crates require illumos. Use nextest with
exclusions:

```bash
cargo nextest run --workspace \
  --exclude ddm \
  --exclude ddmd \
  --exclude mg-tests \
  --exclude falcon-lab \
  --exclude lab
```

Full integration tests require illumos/Helios and run in CI via
Buildomat. Lab tests (`clab`, `interop-lab`, `falcon-lab`) require
their respective environments (containerlab, Docker, libfalcon).

## Verification

All work should compile and pass these checks before submitting:

```bash
cargo clippy --all-targets -- --deny warnings
cargo fmt --all --check
cargo xtask openapi check
```

## Key Patterns

### Concurrency Model
- **BGP sessions**: One OS thread per `SessionRunner` (FSM loop).
  Channel-based event passing.
- **Admin APIs/metrics**: Tokio async tasks.
- **Shared state**: `Arc<Mutex<T>>` with helper macros `lock!`,
  `read_lock!`, `write_lock!`.
- **Shutdown**: `AtomicBool` flags checked in loops.

### Generics for Testability
- `Router<Cnx: BgpConnection>` — abstract over connection type.
- Production: TCP connections. Tests: channel-based connections.
- Platform traits in mg-lower: `Dpd`, `Ddm`, `SwitchZone`.

### Logging
- Structured slog with component/module/unit hierarchy.
- Constants: `COMPONENT_BGP`, `MOD_ROUTER`, `UNIT_*`.
- Custom macros: `session_log!`, `collision_log!`, `rdb_log!`,
  `mgl_log!`, `dpd_log!`.

### Error Handling
- `thiserror` for structured error types in libraries.
- `anyhow::Result` in CLI tools.
- `HttpError` conversions for Dropshot API handlers.
- Broken pipe handling in CLI tools (`println_nopipe!` macro).

## Platform Notes

- `mg-lower` only compiles/runs on illumos (feature-gated in mgd).
- Platform-specific code guarded by `cfg(target_os = "illumos")`.
- The `lab` and `package` crates are workspace members but not
  default members (require illumos).
- BGP sessions use raw TCP (port 179) — not HTTP. The
  admin/management API is separate from the protocol.
- RIB database path defaults to `/var/run/rdb` (mgd) and
  `/var/run/ddmdb` (ddmd).

---

## API Type Versioning

The admin API (`mg-api`) is versioned via
`dropshot-api-manager-types::api_versions`. The version list and
API trait live in `mg-api/src/lib.rs`.

### When You Need to Change an API Type

When modifying a type that appears in an API endpoint's request or
response, you must preserve backward compatibility for older API
versions. The process:

1. **Copy the current type to a versioned name.** If the type is
   `Foo`, copy it to `FooV{N}` where `{N}` is one less than the
   version that introduces the new type. If versioned copies already
   exist, use the next available number. For example, if `FooV1` and
   `FooV2` exist, the current `Foo` becomes `FooV3`.

2. **Add `#[schemars(rename = "Foo")]`** to the old copy. This makes
   the OpenAPI spec use the original name `Foo` for all versions, so
   clients don't see the internal suffix.

3. **Modify the original `Foo`** with your changes (new fields,
   changed types, etc.). It keeps the name `Foo` with no schemars
   rename — it IS `Foo` in the latest OpenAPI spec.

4. **Implement `From<Foo> for FooV{N}`** so the API layer can
   convert the current internal type to the old API type when
   serving older API versions.

5. **Update endpoints** to use version ranges:
   - Old endpoint: `versions = ..VERSION_X` uses `FooV{N}`
   - New endpoint: `versions = VERSION_X..` uses `Foo`

6. **Add a comment** on the old type documenting which API versions
   it serves and when it can be deleted.

### Example

Suppose `VERSION_X` introduces a new field on `Foo`. The old `Foo`
becomes `FooV1`, and the new `Foo` gets the added field:

```rust
/// Previous version of Foo.
/// Used for API versions before VERSION_X.
/// Delete when VERSION_X is the minimum supported version.
#[derive(/* derives */)]
#[schemars(rename = "Foo")]       // <-- OpenAPI still calls it "Foo"
pub struct FooV1 {
    pub field_a: String,
    pub field_b: u64,
}

impl From<Foo> for FooV1 { /* field-by-field conversion */ }

/// Current Foo (VERSION_X+).
#[derive(/* derives */)]
pub struct Foo {
    pub field_a: String,
    pub field_b: u64,
    pub field_c: Option<String>,  // NEW
}
```

And in the API endpoint:

```rust
// Old endpoint serves versions before VERSION_X
#[endpoint { versions = ..VERSION_X }]
async fn get_foo(...) -> FooV1;

// New endpoint serves VERSION_X onward
#[endpoint { versions = VERSION_X.. }]
async fn get_foo_v2(...) -> Foo;
```

For real examples, search for `#[schemars(rename` in the codebase —
`rdb/src/types.rs`, `bgp/src/params.rs`, `bgp/src/session.rs`, and
`mg-api/src/lib.rs` all contain versioned types following this
pattern.

### Key Rules

- Versioned types are **never used internally**. The FSM, RIB, and
  all internal code use the current `Foo`. Conversion to `FooV{N}`
  happens only at the API boundary.
- The `#[schemars(rename)]` is critical — without it, the OpenAPI
  spec would expose the internal suffix to clients.
- The `From` impl handles lossy conversions gracefully (e.g.,
  `PeerId::Interface` maps to `Ipv6Addr::UNSPECIFIED` in V1).

After any API type change, regenerate and verify the OpenAPI specs:

```bash
cargo build --bin mgd
cargo xtask openapi generate
cargo xtask openapi check
```

---

## BGP Test Address Allocation

BGP tests in `bgp/src/test.rs` use two connection backends:

- **Channel-based** (`BgpConnectionChannel` / `BgpListenerChannel`)
  — in-process channels, no real sockets. Fast, deterministic.
- **TCP-based** (`BgpConnectionTcp` / `BgpListenerTcp`) — real TCP
  sockets on loopback.

Every test must use **unique socket addresses** to avoid conflicts
when nextest runs tests in parallel. Addresses are allocated
sequentially (hex for `3fff::`) from distinct ranges.

### Address Ranges

| Range | Purpose | Real sockets? |
|---|---|---|
| `10.0.0.{1..}` | IPv4 channel + some TCP | Channel: no. TCP: yes |
| `127.0.0.{1..}` | IPv4 TCP tests | Yes (loopback) |
| `3fff::{0..}` | IPv6 numbered (channel + TCP) | Channel: no. TCP: yes |
| `fe80::{1,2}` + scope_id | IPv6 unnumbered | No (virtual) |

All use port `TEST_BGP_PORT` (10179).

### Adding a New Test

To find the current highest-allocated addresses, grep for
`sockaddr!` in `bgp/src/test.rs` and pick the next sequential value
in the appropriate range.

1. **TCP tests must not share addresses with other TCP tests.** Two
   TCP tests binding the same IP:port will fail when run in parallel.
   Channel tests don't bind real sockets, so channel-only address
   reuse is safe (but not recommended for clarity).

2. **Each test gets a pair** (or triple for 3-router topologies).
   Allocate N consecutive addresses for an N-router test. IPv6
   addresses (`3fff::`) are allocated sequentially in hex.

3. **Unnumbered tests** reuse `fe80::1`/`fe80::2` and call
   `next_scope_id()` for isolation. Don't invent new link-local
   addresses without reason.

4. **Route advertisement prefixes** are separate from session
   addresses:
   - IPv4: `generate_test_prefixes_v4(count)` from `10.0.0.0/24`
   - IPv6: `generate_test_prefixes_v6(count)` from `3fff:db8:0::/48`

### Test Infrastructure

**Setup**: `test_setup::<Cnx, Listener>(name, routers)` is the
standard harness. TCP variants install loopback IPs via
`LoopbackIpManager`; channel variants skip this.

**Polling macros** (defined in `mg-common/src/test.rs`):
- `wait_for!(expr, msg)` — polls at 1s intervals, up to 30
  iterations.
- `wait_for_eq!(lhs, rhs, msg)` — shorthand for equality polling.
- `wait_for_neq!(lhs, rhs, msg)` — shorthand for inequality
  polling.

**Counter-based synchronization**: For channel tests where FSM state
transitions happen in microseconds, poll
`session.counters.transitions_to_established` instead of
`session.state()` — the state may cycle through Established and back
before the 1-second poll fires.

**Passive/active pairing**: Set one router `passive: true` and the
other `passive: false` to prevent connection collisions during
re-establishment. Required for tests that reset sessions and assert
on `last_reset.reason` (collisions overwrite the reason).
