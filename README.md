Maghemite
=========

A suite of routing protocol implementations written in Rust.

Routing protocols are commonly broken up into an upper half and a lower half.
The upper half is responsible for discovering other routers, forming peering
relationships, and exchanging routes. The lower half is responsible for making
packet forwarding decisions based on the routing tables established by an
upper half. Maghemite implements upper halves for the protocols listed below
with support for the lower-half data planes listed below.

## Protocols

- [x] [DDM](ddm): Delay Driven Multipath
- [x] [BGP](bgp): Border Gateway Protocol
- [x] [BFD](bfd): Bidirectional Forwarding Detection
- [x] [Static](mgd/src/static_admin.rs): Static route specifications (e.g. no protocol involved)

## Supported Data Planes

- [x] illumos/Helios 2
- [x] Sidecar/Dendrite

## Tooling

- [x] [ddmadm](ddmadm)
- [x] [mgadm](mgadm)

## APIs

- [x] [DDM OpenAPI](openapi/ddm-admin/ddm-admin-latest.json)
- [x] [DDM Rust Client Library](ddm-admin-client)
- [x] [MGD OpenAPI](openapi/mg-admin/mg-admin-latest.json)
- [x] [MGD Rust Client Library](mg-admin-client)

## Delay Driven Multipath (DDM)

DDM is the protocol that implements routing between sleds within a rack and
across racks. DDM is a simple path-vector routing protocol. It's described in
detail in [RFD 347](https://rfd.shared.oxide.computer/rfd/0347). DDM is the
sole routing protocol that runs on the network interconnecting sleds and racks,
commonly referred to as the underlay network. Because of that, it has its own
standalone routing information base (RIB).

## External Routing Protocols

Unlike DDM, external routing is a coordination among several protocols and
configuration mechanisms. Currently, these include BGP, BFD, and static routing.
These all share a common RIB. They also live in a common daemon `mgd`. Each
protocol is implemented as a library and `mgd` manages execution for each
protocol. The RIB for these protocols lives in [rib](rdb) and the lower half
responsible for synchronizing RIB state to the underlying forwarding platform
lives in [mg-lower](mg-lower). The lower half is also written as a library
whose execution is managed by `mgd`. This compile-time library-centric
architecture is by design.

## Testing

- [DDM integration tests](tests/src/ddm.rs)
- [BGP integration tests](bgp/src/test.rs)
- [BFD integration tests](bfd/src/lib.rs#L282)

### Lower-half API endpoints

On illumos, by default, the `mgd` lower half uses Dendrite's `dpd` API at
`[::1]:12224` and DDM's `ddmd` admin API at `[::1]:8000`.

The `mgd run` options `--dendrite-addr` and `--ddm-addr` override these
endpoints with explicit socket addresses. Test fixtures can bind each API to
port `0` and pass the allocated addresses to `mgd`. This comes into play for
concurrent tests (e.g., [Omicron's integration tests][omicron-tests] under
nextest), where each test runs its own `dpd` and `ddmd` instances.

[omicron-tests]: https://github.com/oxidecomputer/omicron/tree/main/nexus/tests/integration_tests
