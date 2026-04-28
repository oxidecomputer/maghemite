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

```
+-------------------+        +---------------------------+
| <name>-types      | -----> | <name>-types-versions     |
| (facade re-export)|        | v1, v2, ..., latest       |
+-------------------+        +---------------------------+
       ^                                  ^
       | depended on by mgd, ddmd,        | depended on by *-types,
       | bgp, rdb, mg-common, ...         | by other *-types-versions,
                                          | and by the dropshot-apis crate
```

Two structural rules from RFD 619 that drive the organization:

1. **Versions crates are leaves.** A `*-types-versions` crate may depend on
   other `*-types-versions` crates and on small leaf utilities, but **not**
   on any business-logic crate (`bgp`, `rdb`, `mgd`, `ddm`, `mg-common`,
   ...). Code inside `vN/` modules must reference foreign types through
   versioned identifiers (`crate::v1::...` or
   `<other_versions_crate>::vN::...`), never through the facade.
2. **`impls/` is for `latest::*` glue.** Cross-version `From` impls and
   inherent methods on the latest form may live in
   `<crate>-versions/src/impls/`. Anything that needs to reach into a
   business-logic crate must live in the facade crate or, if both source
   and target are foreign, in the call-site crate.

## Crate map

| Facade crate        | Versions crate              | Schema-published surface                                                                 |
|---------------------|-----------------------------|------------------------------------------------------------------------------------------|
| `rdb-types`         | `rdb-types-versions`        | `Path`, `BgpPathProperties`, `Prefix`/`Prefix4`/`Prefix6`, `PeerId`, BFD/policy types    |
| `bgp-types`         | `bgp-types-versions`        | BGP wire messages (`Message`, `OpenMessage`, `UpdateMessage`, ...) and session history   |
| `mg-common-types`   | `mg-common-types-versions`  | Types shared between the Maghemite and DDM admin APIs                                    |
| `mg-types`          | `mg-types-versions`         | Maghemite-admin types: BGP config (`Neighbor`, `BgpPeerConfig`, ...), RIB views, NDP, BFD |
| `ddm-types`         | `ddm-types-versions`        | DDM-admin types (`PeerInfo`, `TunnelRoute`, ...)                                          |

The facade crate of each pair is what the rest of the workspace imports.
The versions crate is what the dropshot-apis crate uses to bind concrete
shapes to specific API versions.

### Version modules per crate

Each versions crate maps API-version identifiers (declared by the relevant
`api_versions!` macro) to `vN` modules via `#[path = "..."]`:

- `bgp-types-versions`: `v1` (initial), `v2` (ipv6_basic), `v4` (mp_bgp)
- `rdb-types-versions`: `v1` (initial), `v4` (mp_bgp), `v5` (unnumbered)
- `mg-common-types-versions`: `v1` (initial)
- `mg-types-versions`: `v1` (initial), `v2` (ipv6_basic), `v3`
  (switch_identifiers), `v4` (mp_bgp), `v5` (unnumbered), `v6`
  (rib_exported_string_key), `v7` (operation_id_cleanup), `v8`
  (bgp_src_addr)
- `ddm-types-versions`: `v1` (initial)

`latest.rs` re-exports the canonical form of each type from the version
where its current shape was first introduced.

## Type to crate quick reference

Most common items, with their canonical version path and the facade name
exported by the paired facade crate.

### RIB / paths / prefixes

- `Path`, `BgpPathProperties`
  - `rdb_types_versions::v{1,5}::path::*` (latest = v5)
  - facade: `rdb_types::Path`, `rdb_types::BgpPathProperties`
- `Prefix`, `Prefix4`, `Prefix6`, `AddressFamily`
  - `rdb_types_versions::v1::prefix::*`
  - facade: `rdb_types::Prefix*`
- `PeerId` (peer-session identity)
  - `rdb_types_versions::v1::peer::PeerId`
  - facade: `rdb_types::PeerId`
- `Rib`, `RibQuery`, `GetRibResult`, `BestpathFanoutRequest/Response`
  - `mg_types_versions::v{1,2,5}::rib::*` (latest = v5)
  - facade: `mg_types::rib::*`
  - The `rdb::db::Rib -> vN::rib::Rib` conversions live as free functions
    in `mg-types/src/rib.rs` (`rib_latest_from_rdb`, `rib_v1_from_rdb`):
    they cannot live in `mg-types-versions` (orphan rule + leaf-crate
    rule).

### BGP wire messages and session history

- `Message`, `OpenMessage`, `UpdateMessage`, `NotificationMessage`,
  `RouteRefreshMessage`, `Capability`, `OptionalParameter`, `ErrorSubcode`,
  `MessageKind`, `MessageConvertError`
  - `bgp_types_versions::v{1,4}::messages::*` (latest = v4)
  - facade: `bgp_types::messages::*`
- `MessageHistory`, `MessageHistoryEntry`, `FsmEventRecord`,
  `FsmEventCategory`, `FsmStateKind`, `ConnectionId`, `ConnectionDirection`
  - `bgp_types_versions::v{1,2}::session::*` (latest = v2)
  - facade: `bgp_types::session::*`
- Internal wire-parse helpers (`UpdateParseError`, `AttributeAction`, ...)
  - `bgp_types_versions::parse` -- non-published, not re-exported by the
    facade. They live in the versions crate because public-field embeds in
    `UpdateMessage` keep them tightly coupled.

### Versioned BGP config and per-peer types

- `Neighbor`, `UnnumberedNeighbor`, `BgpPeerConfig`,
  `UnnumberedBgpPeerConfig`, `BgpPeerParameters`, `ApplyRequest`,
  `BgpRouterInfo`
  - `mg_types_versions::v{1,4,5,8}::bgp::*` (latest = v8 for most;
    UnnumberedNeighbor / UnnumberedBgpPeerConfig first appear at v5)
  - facade: `mg_types::bgp::*`
- `PeerInfo`, `PeerTimers`, `DynamicTimerInfo`, `NeighborResetOp`
  - `mg_types_versions::v{1,2,4,5}::bgp::*`
  - facade: `mg_types::bgp::*`
- `Router`, `Origin4`/`Origin6`, `AfiSafi`, `BgpCapability`,
  `Ipv4UnicastConfig`/`Ipv6UnicastConfig`, `JitterRange`, `PeerCounters`,
  `StaticTimerInfo`, `CheckerSource`, `ShaperSource`
  - `mg_types_versions::v{1,2,4}::bgp::*` (the version where each shape
    first appears)
  - facade: `mg_types::bgp::*`

### BFD

- `BfdPeerInfo`, `BfdPeerConfig`
  - `rdb_types_versions::v1::bfd::*` (the schema-published carriers)
  - facade: `rdb_types::*`
- `mg_types_versions::v1::bfd` re-exposes BFD shapes used by the mg admin
  API.

### DDM admin

- `PeerInfo`, `TunnelRoute`, `OriginatedRoute`, ...
  - `ddm_types_versions::v1::*`
  - facade: `ddm_types::*`

### Static routes, NDP, switch

- `StaticRoute4`, `StaticRoute6`, `AddStaticRoute*Request`,
  `DeleteStaticRoute*Request`
  - `mg_types_versions::v{1,2}::static_routes::*`
  - facade: `mg_types::static_routes::*`
  - `StaticRouteN -> rdb::StaticRouteKey` conversions live as private free
    fns in `mgd/src/static_admin.rs` (orphan-rule + leaf-crate constraints
    rule out putting them in either versions crate or in `rdb`).
- NDP types: `mg_types_versions::v5::ndp::*`, facade `mg_types::ndp::*`
- Switch identifiers: `mg_types_versions::v3::switch::*`, facade
  `mg_types::switch::*`

## Adding a new published type

1. **Pick the canonical version.** The first API version where the new
   type's current shape is exposed. Add the type definition to
   `<crate>-types-versions/src/<version_dir>/<module>.rs` (or create a new
   submodule there). Use only versioned identifiers in field types --
   either `crate::v<canon>::...` from this crate or
   `<other_versions_crate>::v<canon>::...` from a foreign versions crate.
2. **Re-export from `latest`.** Add a `pub use crate::v<canon>::...` line
   to the appropriate `pub mod <area>` block in
   `<crate>-types-versions/src/latest.rs`.
3. **Re-export from the facade.** Add the type to the corresponding
   `<crate>-types/src/<area>.rs` (or `lib.rs`) glob/explicit re-export.
4. **Cross-version conversions.** If older API versions need a separate
   shape, define `<TypeName>V<N>` in the older module with
   `#[schemars(rename = "<TypeName>")]` and add a `From` impl in
   `<crate>-types-versions/src/impls/<module>.rs` between the latest form
   and the older form. Conversions involving business-logic types live in
   the facade crate or at the call site.
5. **Schema/OpenAPI dance.** Run `cargo run -p xtask -- openapi check`
   after each change; if you intentionally introduce a new schema name,
   bless the new doc rather than editing a previous version's blessed
   document.

## Adding a new API version

The lib.rs of each versions crate has the canonical recipe in its
module-level doc comment; the short form:

1. Bump `api_versions!` in the relevant trait (`mg-api`, `ddm-admin-api`,
   etc.) with the new identifier.
2. Create `<crate>-types-versions/src/<version_dir>/mod.rs` mirroring the
   prior version's structure. New types go in the new module; types whose
   shapes did not change can be left at their existing version path.
3. Add `#[path = "<version_dir>/mod.rs"] pub mod vN;` at the bottom of
   `lib.rs`.
4. Update `latest.rs` so it re-exports from the new module wherever the
   shape changed.
5. Add cross-version `From` impls in `impls/` for every type whose shape
   changed (latest <-> older form).
6. Run the dropshot-apis manage tool and the OpenAPI check; bless the new
   versioned document.

## Internal vs published types

A type is "published" when it appears in at least one blessed OpenAPI
document. Published types live in a `*-types-versions` crate.

A type is "internal" when it is used only by business-logic crates and
never appears in a schema. Internal types stay in their owning
business-logic crate (`bgp`, `rdb`, `ddm`, `mg-common`, `mgd`).

A small grey zone exists: a type may be unpublished but reachable as a
public field of a published type. Examples and how they are handled:

- `bgp_types_versions::parse` -- contains `UpdateParseErrorReason`,
  `AttributeAction`, etc. They are referenced by `UpdateMessage::errors`,
  but the field is `#[serde(skip)]` / `#[schemars(skip)]`, so the types
  are not in any schema. They live in the versions crate because moving
  them would force a `bgp_types_versions -> bgp` dependency edge, which
  the leaf-crate rule forbids.
- `rdb::types::StaticRouteKey` -- non-schema, stays in `rdb`. Conversions
  to/from versioned shapes live at call sites in `mgd`.

When in doubt: if the type appears in `rg JsonSchema <file>` and shows up
in any blessed OpenAPI doc's `components.schemas`, it's published.

## Reference

- [RFD 619] -- canonical guidance.
- `claude/rfd-619-migration-playbook.md` -- lessons learned during the
  migration, including chunk patterns and orphan-rule pitfalls.
- `docs/bgp-architecture.md` -- BGP runtime architecture (separate
  concern, but cross-references many of the types listed above).
