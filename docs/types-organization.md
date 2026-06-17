# Maghemite type organization

This document is a tour, for someone new to the repo, of where
Maghemite's HTTP-API types live and how they get from a versioned
definition to a business-logic call site. The rules are
[RFD 619 "Managing types across Dropshot API versions"][rfd619]
applied to Maghemite. **RFD 619 is the source of truth**; if this
guide and the RFD ever disagree, the RFD wins and this document is
the bug.

[rfd619]: https://rfd.shared.oxide.computer/rfd/619
[migrate-guide]: https://github.com/oxidecomputer/dropshot-api-manager/blob/main/guides/migrating-to-versions-crate.md
[new-version-guide]: https://github.com/oxidecomputer/dropshot-api-manager/blob/main/guides/new-version.md

## Why versioning matters here

Maghemite exposes two Dropshot HTTP APIs that the rest of the Oxide
control plane drives. Both are *server-side-versioned* per
[RFD 532][rfd532]: a single server binary can talk to clients that
were built against any blessed prior version of the schema. The
schema lives in the workspace as code, and every prior wire shape we
ever shipped must continue to compile so the server can decode and
re-encode requests for older clients.

[rfd532]: https://rfd.shared.oxide.computer/rfd/532

RFD 619 prescribes a crate layout that keeps that property workable.
The rest of this document is just that layout, made concrete.

## The crate map

Each API gets four crates that play four different roles:

| Role             | mg-admin API              | ddm-admin API              |
|------------------|---------------------------|----------------------------|
| Versions crate   | `mg-api-types-versions`   | `ddm-api-types-versions`   |
| Types crate      | `mg-api-types`            | `ddm-api-types`            |
| API trait crate  | `mg-api`                  | `ddm-api`                  |
| Progenitor client| `mg-admin-client`         | `ddm-admin-client`         |

The dependency graph (RFD 619 §"Determinations / Overview") looks
like this:

```
            +-------------------------+
            | <api>-types-versions    |  canonical home of every
            | (vN modules, impls,     |  published type, in every
            |  latest re-exports)     |  version
            +-------------------------+
              ^         ^         ^
              |         |         |
   +----------------+ +-----+ +------------------+
   | <api>-types    | | api | | progenitor       |
   | (facade,       | | trait | client crate     |
   |  wildcard      | | crate | (replace = ...   |
   |  re-exports    | | (-api)| references       |
   |  from `latest`)| |       | `latest::*`)     |
   +----------------+ +-----+ +------------------+
            ^
            |
   +--------------------+
   | business logic     |
   | (mgd, bgp, rdb,    |
   |  mg-lower, mgadm,  |
   |  ddm, ddmadm)      |
   +--------------------+
```

Three rules fall out of this:

1. **Every published type lives in a versions crate.** A "published
   type" is anything that ends up in an OpenAPI document — directly,
   or because a published type embeds it transitively. The types
   crate is a thin facade; the API trait names types from the
   versions crate; the client's `replace = { … }` block names types
   from the versions crate. The versions crate is the *only* place
   the type is defined.
2. **Business logic never imports from a versions crate.** Code
   under `bgp/`, `rdb/`, `mgd/`, `mg-lower/`, etc. imports through
   the types crate (`use mg_api_types::bgp::config::Neighbor;`).
   The facade wildcard-re-exports the `latest::*` namespace, so
   business logic is automatically tracking the latest schema and
   never has to think about prior versions.
3. **Cross-version conversion code is self-contained.** It lives
   in the versions crate, on the path between two `vN` modules.
   The conversions never leak into business logic.
4. **Floating paths mirror source paths exactly.** For every type
   defined at `crate::vN::AREA::SUBMODULE::Type` in the versions
   crate, replacing `vN` with `latest` yields the floating
   identifier (`crate::latest::AREA::SUBMODULE::Type`), and
   stripping the `_versions::latest` segment yields the facade
   identifier (`mg_api_types::AREA::SUBMODULE::Type`). No type is
   "hoisted" up a namespace at the facade — disk shape and consumer
   shape are the same shape.

## Inside `<api>-types-versions`

This is the only crate in the workspace where a type's version
matters. Once you understand its layout, the rest follows.

### `lib.rs` — the version table

```rust
// mg-api-types-versions/src/lib.rs
mod impls;
pub mod latest;
#[path = "initial/mod.rs"]            pub mod v1;
#[path = "ipv6_basic/mod.rs"]         pub mod v2;
#[path = "switch_identifiers/mod.rs"] pub mod v3;
#[path = "mp_bgp/mod.rs"]             pub mod v4;
#[path = "unnumbered/mod.rs"]         pub mod v5;
#[path = "bgp_src_addr/mod.rs"]       pub mod v8;
```

Two things this is doing:

- **The `vN` identifier is what everyone imports**
  (`use mg_api_types_versions::{latest, v1, v4};`), but the
  directory on disk uses the version's lowercase **named**
  identifier from the `api_versions!` macro in `mg-api/src/lib.rs`.
  RFD 619 picks this so two developers landing v9 and v10
  concurrently hit the merge conflict in `lib.rs` (easy to resolve)
  instead of inside `vN/` (where it would be much harder).
- **Only versions that added or changed a published type get a
  module.** mg-admin also has v6, v7, and v9 — endpoint renames and
  operation-id cleanups that touched no schema, so no version
  module exists.

`lib.rs` is `mod`/`pub mod` declarations only; there is no code in
it.

### A version module is a tree of `pub mod` declarations

Each version module's `mod.rs` is a brief doc comment plus
`pub mod` declarations — no logic, no type definitions. The
submodule layout corresponds to API areas: `bfd`, `bgp`, `rdb`,
`rib`, `ndp`, `switch`, `static_routes`. When an area is large,
those split further: `bgp/{config, messages, peer, policy, session}`,
`rdb/{path, prefix, router, neighbor}`.

Inside a version module's leaf files, two rules govern paths to
other types:

- **Same-version siblings: `super::`.**
  `v1::bgp::config` writing `super::messages::OpenMessage` always
  means "the v1 OpenMessage". You never see `crate::v1::…` from a
  v1 submodule.
- **Prior-version references: `crate::vN::…` (versioned).**
  v4 referencing v1's prefix shape writes
  `use crate::v1::rdb::prefix::Prefix;` — a fixed path that will
  never resolve to anything else. **Never** use a floating
  identifier (`crate::latest::…` or the facade `mg_api_types::…`)
  inside a version module: the whole point of the version module is
  that its shape is frozen, and a floating import would silently
  change shape under it.

### Cross-version conversions live in the newer version

When a type changes shape from `vN` to `vM` (M > N), the conversion
code lives in `vM`, alongside the new shape. Older modules stay
immutable — adding a v10 never requires editing the v9 module.

The conversion direction is dictated by how the type is used:

- **Request types**: older → newer (the server upgrades incoming
  requests to the latest internal shape).
- **Response types**: newer → older (the server downgrades outgoing
  responses to the prior wire shape).
- **Bidirectional types**: both.

`From` / `TryFrom` are the default. When a conversion needs data
the type doesn't carry (e.g. server state from `Self::Context`), it
becomes a named `from_vN` / `into_vN` method instead, and the
corresponding API endpoint becomes a required method on the trait
(see "API trait" below).

Most of the time conversions only span one version — go through
intermediate versions if you need to skip further. The
[`v4::bgp::messages` → `v1::bgp::messages` PathAttribute downgrade][rfd-skip-example]
is an annotated example of when the one-hop rule is consciously
broken and why.

[rfd-skip-example]: ../mg-api-types/versions/src/mp_bgp/bgp/messages.rs

### `latest.rs` — the floating-identifier table

`latest.rs` re-exports the newest version of every published type
under a `latest::…` path. The facade points at it; progenitor
`replace = { … }` blocks point at it; the API trait names latest
endpoints through it.

Two rules from RFD 619 §"Versions crates re-export the latest
versions of each type":

- **One re-export per line**, with the version it comes from
  visible in the source path.
- **Within each submodule, re-exports are grouped by version
  ascending, separated by blank lines.** No wildcards.

```rust
// mg-api-types-versions/src/latest.rs (excerpt)
pub mod bgp {
    pub mod config {
        pub use crate::v1::bgp::config::AsnSelector;
        pub use crate::v1::bgp::config::Router;
        // ...

        pub use crate::v4::bgp::config::PeerInfo;
        pub use crate::v4::bgp::config::PeerTimers;
        // ...

        pub use crate::v8::bgp::config::Neighbor;
        pub use crate::v8::bgp::config::UnnumberedNeighbor;
        // ...
    }

    pub mod peer {
        pub use crate::v1::bgp::peer::PeerId;
    }

    pub mod error {                                  // helper block:
        pub use crate::impls::bgp::error::WireError; //   non-published
        // ...                                       //   types re-exported
    }                                                //   from impls/.
}
```

The submodule namespaces in `latest.rs` exactly mirror the source
submodule names in each `vN` directory. Adding a hoist (i.e.
`pub use crate::v1::bgp::config::Router;` directly under
`pub mod bgp`, dropping the `config` segment) would break the
substitution property and is not allowed.

Two practical consequences:

- You can read a type's canonical version at a glance.
- Two PRs that both touch the same `pub mod` block will produce a
  merge conflict in `latest.rs`, forcing a human decision instead of
  silently dropping one side's re-export.

### `impls/` — functional code on the latest shape

`impls/` is **private to the versions crate** (`mod impls;`, not
`pub mod`). It mirrors the `latest::` submodule tree and holds:

- inherent methods on the latest forms,
- foreign-trait impls (`Display`, `FromStr`, `Ord`, `slog::Value`,
  …),
- helper types (e.g. wire-parse error enums) referenced by those
  impls.

Within `impls/`, types are always named through floating
`crate::latest::…` identifiers — so when a type's canonical version
changes, the impl blocks track it automatically with zero code
edits.

Two things that look like they belong in `impls/` but **don't**:

- **Schema-bearing trait impls** (`Serialize`, `Deserialize`,
  `JsonSchema`, `Debug`). These live next to each version's type
  definition, so every version's schema is self-contained.
- **Cross-version `From` / `TryFrom`.** Those live in the newer
  version's module, as described above. `impls/` is reserved for
  *latest-only* code.

Helper types declared in `impls/` that need to be public (e.g.
`MessageConvertError`, `UpdateParseErrorReason`) are re-exported by
name from `latest.rs` in a trailing block after all `vN` groups.

## Inside `<api>-types`

The types crate is one file per area, each a single wildcard
re-export:

```rust
// mg-api-types/src/bgp.rs
pub use mg_api_types_versions::latest::bgp::*;
```

That is the whole file. Business logic writes
`use mg_api_types::bgp::config::Neighbor;`, and the path mirrors
`latest::` exactly with `_versions::latest` stripped out. When a
type's canonical version bumps, the facade automatically follows.

## Inside `<api>-api` (the API trait)

The API trait imports both `latest` and any prior `vN` modules it
needs:

```rust
// mg-api/src/lib.rs (excerpt)
use mg_api_types_versions::{latest, v1, v2, v4, v5};
```

Two patterns:

- **Latest endpoints** name types via `latest::…` paths and have
  unsuffixed method names (`fn create_neighbor`).
- **Prior-version endpoints** name types via `vN::…` paths, append
  the *introducing* version as a suffix (`fn create_neighbor_v5`,
  `fn create_neighbor_v4`, `fn create_neighbor_v1`), and set
  `operation_id = "<base>"` in the endpoint attribute so the
  generated client method covers all versions under one name.

Prior-version endpoints come in two flavors:

1. **Provided default methods**, when the type conversion can be
   expressed structurally. The default forwards through
   `Self::<latest_method>` and a `.map(Into::into)` / `.try_map(…)`.
   The implementation never has to write a body for these.
2. **Required methods**, when the conversion needs server state
   (e.g. the live session table, the rdb). The implementation
   provides the body; a comment on the trait method explains
   *why* it can't be a provided default. The bulk of the v1/v2/v4
   neighbor and history endpoints fall into this category because
   the per-version response is computed from `Self::Context` at the
   shape the older client expects.

## Inside `<api>-admin-client`

```rust
// mg-admin-client/src/lib.rs (excerpt)
progenitor::generate_api!(
    spec = "../openapi/mg-admin/mg-admin-latest.json",
    replace = {
        AddressFamily = mg_api_types_versions::latest::rdb::rib::AddressFamily,
        ProtocolFilter = mg_api_types_versions::latest::rdb::rib::ProtocolFilter,
    },
);
```

`replace` always points at `latest::…` — the floating identifier —
because the client is generated from the *latest* OpenAPI document.
Pointing at a versioned identifier here would let the source type
drift from the wire schema when the type bumps a version. (RFD 619
§"In client crates, `replace` statements use identifiers matching
the corresponding client version".)

## Where does my type live?

Open `mg-api-types-versions/src/latest.rs` and search for the
type. The `pub use crate::vN::path::to::TypeName;` line points
straight at the canonical version module on disk. That is the only
place the type is defined.

For the *facade* path business logic uses, strip
`mg_api_types_versions::latest::` from the front:
`mg_api_types_versions::latest::rdb::rib::AddressFamily` is reached as
`mg_api_types::rdb::rib::AddressFamily`.

## Walkthrough: adding a new published type to the latest version

Say the latest version is v8 and you need a new `RouteHint` type on
a request body that's already in v8.

1. Add `pub struct RouteHint { … }` to the appropriate v8 submodule
   on disk, e.g.
   `mg-api-types/versions/src/bgp_src_addr/bgp/config.rs`. Field
   types use `super::` (same version, same crate) or `crate::vN::…`
   (prior versions / prior versions of other-crate types).
2. Add `pub use crate::v8::bgp::config::RouteHint;` to the
   matching `pub mod bgp { pub mod config { … } }` block in
   `latest.rs`, in the v8 group within the `config` submodule.
3. If the type needs inherent methods, a `Display` impl, etc., add
   them under `impls/bgp/config.rs` (the mirrored `impls/` tree)
   using `crate::latest::bgp::config::RouteHint` as the path.
4. `mg_api_types::bgp::config::RouteHint` is now reachable from
   business logic automatically — the facade re-exports
   `latest::bgp::config::*`.
5. `cargo xtask openapi generate` to refresh the OpenAPI document
   that will be blessed when this PR merges.

## Walkthrough: adding a new API version

Say you're bumping the `Neighbor` shape and shipping it as version
10, name `MULTIHOMING_SUPPORT`.

1. **Declare the version.** Add `(10, MULTIHOMING_SUPPORT)` to the
   `api_versions!` macro at the top of `mg-api/src/lib.rs`. Keep
   the list sorted, newest first.
2. **Create the version module.** Make
   `mg-api-types/versions/src/multihoming_support/` containing a
   `mod.rs` (only `pub mod` lines, summary doc comment naming the
   change) and the submodules whose types changed (only those —
   v10 does **not** mirror unchanged submodules from earlier
   versions). The new `Neighbor` lives at
   `multihoming_support/bgp/config.rs`.
3. **Wire it into `lib.rs`.** Append
   `#[path = "multihoming_support/mod.rs"] pub mod v10;` to the bottom
   of `lib.rs`. **Do not** leave a blank line between this and the
   prior `pub mod vN;` — rustfmt's stable sort keeps the list ordered
   and the no-blank-line rule guarantees colliding additions merge-
   conflict at this line.
4. **Add conversions** between the new shape and the immediately-
   prior shape. The conversions live in the v10 module (the newer
   side). Request-shaped types convert old → new; response-shaped
   types convert new → old; bidirectional types convert both.
5. **Update `latest.rs`.** Move the affected
   `pub use crate::v8::bgp::config::Neighbor;` line into a new v10
   group (separated by a blank line).
6. **Update the API trait.** The current `create_neighbor`
   continues to use `latest::bgp::Neighbor` (which now resolves to
   v10). Rename the previous `create_neighbor` to `create_neighbor_v8`,
   set `operation_id = "create_neighbor"` on it, and change its
   types to `v8::bgp::config::…`. If the conversion is structural,
   make `create_neighbor_v8` a provided method that forwards through
   `Self::create_neighbor`; if not, make it required and add a
   comment to the trait explaining why.
7. **Regenerate OpenAPI.**
   `cargo run -p xtask -- openapi generate` and then
   `cargo run -p xtask -- openapi check`. Bless the new
   `mg-admin-10.0.0-….json`.

The [new-version guide][new-version-guide] is the canonical
walkthrough with more detail and edge cases.

## Published vs. internal types

A type is **published** when it is reachable, through any chain of
serialized fields, from a Dropshot endpoint argument or return type
— it ends up in an OpenAPI document. Published types live in a
versions crate; nothing else does.

A type is **internal** when only business-logic crates name it and
it never crosses the API boundary. Internal types live in their
owning business-logic crate (`bgp`, `rdb`, `mgd`, `ddm`, `mg-common`,
…) and have no version awareness.

There is a single acknowledged exception in this codebase: the
`#[serde(skip)] errors: Vec<…>` field on
`v4::bgp::messages::UpdateMessage`. It references types in
`crate::impls::bgp::parse::*` from inside a version module, which
RFD 619 normally forbids. The field is `schemars(skip)` too, so it
is not part of any wire schema, and it exists only for in-process
RFC 7606 signaling between the BGP decoder in the `bgp` crate and
its consumers. The deviation is annotated at the use site. Treat
it as a one-off, not a pattern.

## Pointers

- [RFD 619][rfd619] — canonical guidance. Read at least the
  *Determinations* section before any structural change.
- [Migrating to a versions crate][migrate-guide] and
  [adding a new API version][new-version-guide] — the
  dropshot-api-manager step-by-step guides.
- `mg-api/src/lib.rs` — the `api_versions!` table and the
  `MgAdminApi` trait. Authoritative source for which type belongs
  to which endpoint at which version. `ddm-api/src/lib.rs` is the
  same for ddm-admin.
- `mg-api-types-versions/src/lib.rs` — the
  version-number-to-named-directory map for mg-admin.
- `mg-api-types-versions/src/latest.rs` — every floating
  identifier the rest of the workspace uses, in one file.
