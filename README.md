Maghemite
=========

A modular routing stack written in Rust. Maghemite is a collection of routing
protocol implementations. Maghemite separates the function speaking a routing
protocol and managing the distributed state required to implement a protocol -
from managing the underlying packet-pushing data plane. This
protocol-plane/data-plane distinction is commonly referred to as a router's
upper and lower halves respectively. Maghemite decouples the upper and lower
halves of a routing protocol through a `Platform` trait. Upper halves are
written in terms of a `Platform` trait specific to the protocol being
implemented, and lower halves implement `Platform` traits.

## Protocols

- [x] [DDM](ddm): Delay Driven Multipath
- [ ] BGP: Border Gateway Protocol
- [ ] OSPF: Open Shortest Path First
- [ ] Static: Static route specifications (e.g. no protocol involved)

## Platform Implementations

### DDM

- [x] [Local](ddm-local)
- [x] [illumos/Helios](ddm-illumos)
- [x] Sidecar/Dendrite - part of illumos platform implementation

## Tooling

- [x] [ddmadm](ddmadm)

## APIs

- [x] [DDM OpenAPI](ddm-openapi)
- [x] [DDM Rust Client Library](ddm-admin-client]
