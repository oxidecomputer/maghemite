# Maghemite type organization

**Audience**: Developers landing in the codebase after the RFD 619 type
migration who need to know where published types live and how to add new
ones. Read this alongside [RFD 619] (canonical guidance) and
`claude/rfd-619-migration-playbook.md` (lessons learned).

[RFD 619]: https://rfd.shared.oxide.computer/rfd/619

---

## Overview

Schema-published types (anything that appears in a Maghemite or DDM
admin-API OpenAPI document) live in dedicated **versions** crates. Each
versions crate is paired with a small **facade** crate that re-exports the
`latest::*` items so business-logic call sites can stay version-agnostic.

The workspace organizes published types around the *API* they belong to,
not the domain abstraction they describe. Two API-shaped pairs cover the
entire surface:

```
+-------------------+        +---------------------------+
| mg-api-types      | -----> | mg-api-types-versions     |
| (facade re-export)|        | v1, v2, ..., v8, latest   |
+-------------------+        +---------------------------+

+-------------------+        +---------------------------+
| ddm-api-types     | -----> | ddm-api-types-versions    |
| (facade re-export)|        | v1, latest                |
+-------------------+        +---------------------------+
```

Two structural rules from RFD 619 drive the organization:

1. **Versions crates are leaves.** A `*-api-types-versions` crate may
   depend on small leaf utilities (`schemars`, `serde`, `oxnet`, `nom`,
   ...) but **not** on any business-logic crate (`bgp`, `rdb`, `mgd`,
   `ddm`, `mg-common`). Code inside `vN/` modules must reference foreign
   types through versioned identifiers (`crate::v1::...` or
   `<other_versions_crate>::vN::...`), never through the facade.
2. **`impls/` is for `latest::*` glue.** Cross-version `From` impls and
   inherent methods on the latest form may live in
   `<crate>/src/impls/`. Anything that needs to reach into a
   business-logic crate must live in the facade crate or, if both source
   and target are foreign, in the call-site crate.

## Crate map

| Facade crate     | Versions crate            | Schema-published surface                                                                                  |
|------------------|---------------------------|-----------------------------------------------------------------------------------------------------------|
| `mg-api-types`   | `mg-api-types-versions`   | Everything in the Maghemite admin API: BGP wire+session, BGP config, RIB, NDP, BFD, static routes, switch, plus the routing-database types (`Path`, `Prefix`, `PeerId`, ...) it shares with `rdb` |
| `ddm-api-types`  | `ddm-api-types-versions`  | Everything in the DDM admin API: `PeerInfo`, `TunnelRoute`, exchange types, plus shared `TunnelOrigin`/`IpPrefix` net types |

The facade crate of each pair is what the rest of the workspace imports.
The versions crate is what the dropshot-apis crate uses to bind concrete
shapes to specific API versions, and is what `mg-admin-client`'s
progenitor `replace = {}` block points at.

### Version modules per crate

Each versions crate maps API-version identifiers (declared by the
relevant `api_versions!` macro) to `vN` modules via `#[path = "..."]`:

- `mg-api-types-versions`: `v1` (initial), `v2` (ipv6_basic), `v3`
  (switch_identifiers), `v4` (mp_bgp), `v5` (unnumbered), `v6`
  (rib_exported_string_key), `v7` (operation_id_cleanup), `v8`
  (bgp_src_addr).
- `ddm-api-types-versions`: `v1` (initial).

`latest.rs` re-exports the canonical form of each type from the version
where its current shape was first introduced, grouped by `pub mod
<area>` blocks (`bfd`, `bgp`, `bgp::messages`, `bgp::session`, `ndp`,
`rdb`, `rdb::neighbor`, ..., `rib`, `static_routes`, `switch`).

### Internal layout of `mg-api-types-versions`

Per-version modules group sub-areas to keep version-vs-domain navigation
cheap:

```
v1 (initial)/
  bfd.rs                       - BFD wire + admin path-params
  bgp/{messages,session,config}.rs  - wire types, session history, admin config
  rdb/{path,peer,policy,prefix,router,mod}.rs  - routing-database types,
                                                 AddressFamily/ProtocolFilter
  rib.rs
  static_routes.rs
v2 (ipv6_basic)/
  bgp/{session,history}.rs     - v2 wire/session updates plus admin history
  rib.rs
  static_routes.rs
v3 (switch_identifiers)/
  switch.rs
v4 (mp_bgp)/
  bgp/{messages,config}.rs     - MP-BGP wire types and admin config
  rdb/{neighbor,policy}.rs
v5 (unnumbered)/
  bgp.rs                       - unnumbered admin types
  ndp.rs
  rdb/path.rs
  rib.rs
v6, v7, v8/                    - schema-only or small-shape changes
parse.rs, error.rs             - non-published wire-parse helpers
impls/                         - cross-version From impls + inherent methods
                                 on latest forms (bgp, messages, session,
                                 path, peer, policy, prefix, rib)
```

The `vN/bgp/mod.rs` and `vN/rdb/mod.rs` files re-flatten their per-area
sub-modules so existing intra-crate references like
`crate::v1::bgp::CheckerSource` continue to resolve. The wire-message
and session sub-modules stay namespaced (`crate::v1::bgp::messages::*`,
`crate::v2::bgp::session::*`).

### `mg-api-types` facade

`mg-api-types` exposes the latest forms via:

- Domain modules: `mg_api_types::{bfd, bgp, ndp, rib, static_routes,
  switch}` — each re-exports the corresponding `latest::<area>`.
- Flat re-exports of routing-database types at the crate root, for the
  benefit of consumers (notably `mg-admin-client`'s progenitor
  `replace = {}` block):
  `mg_api_types::{Prefix, Prefix4, Prefix6, AddressFamily,
  ProtocolFilter, PeerId, Path, BgpPathProperties, BgpRouterInfo,
  BgpNeighborInfo, BgpNeighborParameters, BgpUnnumberedNeighborInfo,
  ImportExportPolicy, ImportExportPolicy4, ImportExportPolicy6}`.

### `ddm-api-types` facade

`ddm-api-types` exposes `ddm_api_types::{admin, db, exchange, net}`,
each re-exporting the matching `latest::<area>`. The `net` module
contains `TunnelOrigin`, `IpPrefix`, `Ipv4Prefix`, `Ipv6Prefix` — types
that previously lived in a separate `mg-common-types` crate but are
DDM-specific in practice.

### Import conventions for cross-version code

When a file references types from multiple API versions, disambiguate
through versioned module paths, not name-suffix or `as` renames:

- Bring version roots into scope (`use ...::{v1, v4, ...};`) and
  qualify conflicting names at the use site (`v1::area::Foo` vs
  `v4::area::Foo`).
- Items lists for non-conflicting bare names are fine.
- Function-local `as` aliases are acceptable when terseness inside a
  single match expression justifies them; external-crate name
  collisions are fair game for `as` renames.
- Do not introduce name-suffix renames (`as FooV1`, `as FooV6`,
  `as LiveFoo`). The version path *is* the type's identity.

## Type to crate quick reference

Most common items, with their canonical version path. Facade access
follows the rules above (`mg_api_types::<area>::<Type>` for namespaced,
`mg_api_types::<Type>` for the flat routing-database surface).

### RIB / paths / prefixes

- `Path`, `BgpPathProperties`
  - `mg_api_types_versions::v{1,5}::rdb::path::*` (latest = v5)
  - facade: `mg_api_types::Path`, `mg_api_types::BgpPathProperties`
- `Prefix`, `Prefix4`, `Prefix6`, `AddressFamily`, `ProtocolFilter`
  - `mg_api_types_versions::v1::rdb::*`
  - facade: `mg_api_types::{Prefix, Prefix4, Prefix6, AddressFamily,
    ProtocolFilter}`
- `PeerId` (peer-session identity)
  - `mg_api_types_versions::v1::rdb::peer::PeerId`
  - facade: `mg_api_types::PeerId`
- `Rib`, `RibQuery`, `GetRibResult`, `BestpathFanoutRequest/Response`
  - `mg_api_types_versions::v{1,2,5}::rib::*` (latest = v5)
  - facade: `mg_api_types::rib::*`
  - The runtime RIB shape is a re-export of the latest API alias, so
    cross-version conversions live as intra-crate `From` impls in the
    versions crate rather than as free functions in the facade.

### BGP wire messages and session history

- `Message`, `OpenMessage`, `UpdateMessage`, `NotificationMessage`,
  `RouteRefreshMessage`, `Capability`, `OptionalParameter`,
  `ErrorSubcode`, `MessageKind`, `MessageConvertError`
  - `mg_api_types_versions::v{1,4}::bgp::messages::*` (latest = v4)
  - facade: `mg_api_types::bgp::messages::*`
- `MessageHistory`, `MessageHistoryEntry`, `FsmEventRecord`,
  `FsmEventCategory`, `FsmStateKind`, `ConnectionId`,
  `ConnectionDirection`
  - `mg_api_types_versions::v{1,2}::bgp::session::*` (latest = v2)
  - facade: `mg_api_types::bgp::session::*`
- Internal wire-parse helpers (`UpdateParseError`, `AttributeAction`,
  ...)
  - `mg_api_types_versions::parse` — non-published, not re-exported by
    the facade. They live in the versions crate because public-field
    embeds in `UpdateMessage` keep them tightly coupled.

### Versioned BGP config and per-peer types

- `Neighbor`, `UnnumberedNeighbor`, `BgpPeerConfig`,
  `UnnumberedBgpPeerConfig`, `BgpPeerParameters`, `ApplyRequest`,
  `BgpRouterInfo`
  - `mg_api_types_versions::v{1,4,5,8}::bgp::*` (latest = v8 for most;
    `UnnumberedNeighbor` / `UnnumberedBgpPeerConfig` first appear at v5)
  - facade: `mg_api_types::bgp::*`
- `PeerInfo`, `PeerTimers`, `DynamicTimerInfo`, `NeighborResetOp`
  - `mg_api_types_versions::v{1,2,4,5}::bgp::*`
  - facade: `mg_api_types::bgp::*`
- `Router`, `Origin4`/`Origin6`, `AfiSafi`, `BgpCapability`,
  `Ipv4UnicastConfig`/`Ipv6UnicastConfig`, `JitterRange`,
  `PeerCounters`, `StaticTimerInfo`, `CheckerSource`, `ShaperSource`
  - `mg_api_types_versions::v{1,2,4}::bgp::*`
  - facade: `mg_api_types::bgp::*`

### BFD

- `BfdPeerState`, `BfdPeerConfig`, `BfdPeerInfo`, `SessionMode`,
  `DeleteBfdPeerPathParams`
  - `mg_api_types_versions::v1::bfd::*`
  - facade: `mg_api_types::bfd::*`

### DDM admin

- `PeerInfo`, `TunnelRoute`, `OriginatedRoute`, `PrefixMap`,
  `PathVector`, `PathVectorV2`, ...
  - `ddm_api_types_versions::v1::*`
  - facade: `ddm_api_types::{admin, db, exchange}::*`
- `TunnelOrigin`, `IpPrefix`, `Ipv4Prefix`, `Ipv6Prefix`
  - `ddm_api_types_versions::v1::net::*`
  - facade: `ddm_api_types::net::*`

### Static routes, NDP, switch

- `StaticRoute4`, `StaticRoute6`, `AddStaticRoute*Request`,
  `DeleteStaticRoute*Request`
  - `mg_api_types_versions::v{1,2}::static_routes::*`
  - facade: `mg_api_types::static_routes::*`
  - `StaticRouteN -> rdb::StaticRouteKey` conversions live as private
    free fns in `mgd/src/static_admin.rs` (orphan-rule + leaf-crate
    constraints rule out putting them in either versions crate or in
    `rdb`).
- NDP types: `mg_api_types_versions::v5::ndp::*`, facade
  `mg_api_types::ndp::*`.
- Switch identifiers: `mg_api_types_versions::v3::switch::*`, facade
  `mg_api_types::switch::*`.

## Adding a new published type

1. **Pick the canonical version.** The first API version where the new
   type's current shape is exposed. Add the type definition to
   `mg-api-types-versions/src/<version_dir>/<area>/<module>.rs` (or
   create a new submodule there). Use only versioned identifiers in
   field types — `crate::v<canon>::...` or
   `<other_versions_crate>::v<canon>::...`.
2. **Re-export from `latest`.** Add a `pub use crate::v<canon>::...`
   line to the appropriate `pub mod <area>` block in
   `mg-api-types-versions/src/latest.rs`.
3. **Re-export from the facade.** Add the type to the corresponding
   `mg-api-types/src/<area>.rs` (or `lib.rs`) re-export.
4. **Cross-version conversions.** If older API versions need a separate
   shape, define `<TypeName>V<N>` in the older module with
   `#[schemars(rename = "<TypeName>")]` and add a `From` impl in
   `mg-api-types-versions/src/impls/<module>.rs` between the latest
   form and the older form. Conversions involving business-logic types
   live in the facade crate or at the call site.
5. **Schema/OpenAPI dance.** Run `cargo run -p xtask -- openapi check`
   after each change; if you intentionally introduce a new schema name,
   bless the new doc rather than editing a previous version's blessed
   document.

## Adding a new API version

The lib.rs of each versions crate has the canonical recipe in its
module-level doc comment; the short form:

1. Bump `api_versions!` in the relevant trait (`mg-api`,
   `ddm-admin-api`).
2. Create `mg-api-types-versions/src/<version_dir>/mod.rs` mirroring
   the prior version's structure. New types go in the new module;
   types whose shapes did not change can be left at their existing
   version path.
3. Add `#[path = "<version_dir>/mod.rs"] pub mod vN;` at the bottom of
   `lib.rs`.
4. Update `latest.rs` so it re-exports from the new module wherever
   the shape changed.
5. Add cross-version `From` impls in `impls/` for every type whose
   shape changed (latest <-> older form).
6. Run the dropshot-apis manage tool and the OpenAPI check; bless the
   new versioned document.

## Internal vs published types

A type is "published" when it appears in at least one blessed OpenAPI
document. Published types live in a `*-api-types-versions` crate.

A type is "internal" when it is used only by business-logic crates and
never appears in a schema. Internal types stay in their owning
business-logic crate (`bgp`, `rdb`, `ddm`, `mg-common`, `mgd`).

A small grey zone exists: a type may be unpublished but reachable as a
public field of a published type. Examples:

- `mg_api_types_versions::parse` — contains `UpdateParseErrorReason`,
  `AttributeAction`, etc. Referenced by `UpdateMessage::errors`, but
  the field is `#[serde(skip)]` / `#[schemars(skip)]`, so the types
  are not in any schema. They live in the versions crate because
  moving them would force a `mg-api-types-versions -> bgp` dependency
  edge, which the leaf-crate rule forbids.
- `rdb::types::StaticRouteKey` — non-schema, stays in `rdb`.
  Conversions to/from versioned shapes live at call sites in `mgd`.

When in doubt: if the type appears in `rg JsonSchema <file>` and shows
up in any blessed OpenAPI doc's `components.schemas`, it's published.

## Reference

- [RFD 619] — canonical guidance.
- `claude/rfd-619-migration-playbook.md` — lessons learned during the
  migration, including chunk patterns and orphan-rule pitfalls.
- `claude/api-shape-consolidation-plan.md` — the plan that drove the
  six-pair → two-pair consolidation.
- `docs/bgp-architecture.md` — BGP runtime architecture (separate
  concern, but cross-references many of the types listed above).
