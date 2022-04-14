Maghemite
=========

A suite of routing protocol implementations written in Rust.

Routing protocols are commonly broken up into an upper-half and a lower-half.
The upper-half is responsible for discovering other routers, forming peering
relationships, and exchanging routes. The lower half is responsible for making
packet forwarding decisions based on the routing tables established by an
upper-half. Maghemite implements upper-halves for the protocols listed below
with support for the lower-half data planes listed below.

## Protocols

- [x] [DDM](ddm): Delay Driven Multipath
- [ ] BGP: Border Gateway Protocol
- [ ] OSPF: Open Shortest Path First
- [ ] Static: Static route specifications (e.g. no protocol involved)

## Supported Data Planes

- [x] [illumos/Helios](ddm-illumos)
- [x] Sidecar/Dendrite

## Tooling

- [x] [ddmadm](ddmadm)

## APIs

- [x] [DDM OpenAPI](ddm-openapi)
- [x] [DDM Rust Client Library](ddm-admin-client)
