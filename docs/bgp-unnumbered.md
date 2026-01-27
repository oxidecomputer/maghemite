# BGP Unnumbered Design and Implementation

**Author**: Generated Documentation
**Last Updated**: 2026-01-26
**Audience**: Developers working on or integrating with Maghemite's BGP unnumbered implementation

---

## Table of Contents

1. [Overview](#overview)
2. [Background: Why BGP Unnumbered?](#background-why-bgp-unnumbered)
3. [Architecture Overview](#architecture-overview)
4. [NDP Integration](#ndp-integration)
5. [BGP FSM Integration](#bgp-fsm-integration)
6. [Key Design Decisions](#key-design-decisions)
7. [References](#references)

---

## Overview

BGP unnumbered enables BGP peering over IPv6 link-local addresses without requiring globally routable IP addresses on interfaces. This is particularly useful for datacenter underlay networks where IP address allocation overhead is eliminated and the same link-local address can be reused across multiple interfaces.

Maghemite implements BGP unnumbered by integrating **NDP (Neighbor Discovery Protocol)** with the **BGP FSM (Finite State Machine)**:
- NDP discovers peer link-local addresses on configured interfaces
- BGP FSM manages session lifecycle based on discovered peers
- Sessions persist through neighbor changes and reconnect automatically

---

## Background: Why BGP Unnumbered?

### Traditional Numbered BGP

In traditional BGP, each peer is identified by a globally routable IP address:

```
Router A (192.0.2.1) ←→ Router B (192.0.2.2)
```

**Challenges**:
- Requires unique IP subnet per link (wasteful in large fabrics)
- Configuration overhead for address assignment
- IP address exhaustion in large topologies

### BGP Unnumbered Solution

With BGP unnumbered, peers use IPv6 link-local addresses:

```
Router A (fe80::1%eth0) ←→ Router B (fe80::2%eth0)
```

**Benefits**:
- No IP address allocation needed (link-local addresses are self-assigned)
- Same IP can be reused on every interface
- Simplified configuration (just specify interface name)

**Key Challenges Addressed**:
1. **Discovery mechanism**: How do we find the peer's link-local address? → NDP
2. **Session mapping**: How do we route incoming connections to the correct session? → scope_id lookup
3. **Nexthop resolution**: How do we specify which interface to use for routing? → nexthop_interface in Path

---

## Architecture Overview

### High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    UnnumberedManagerNdp                     │
│  ┌──────────────────┐      ┌─────────────────────────────┐  │
│  │ NDP Manager      │      │ scope_id → interface map    │  │
│  │ (per-interface   │      │ (for Dispatcher routing)    │  │
│  │  discovery)      │      └─────────────────────────────┘  │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
           │                               │
           │ NDP queries                   │ scope_id lookup
           ▼                               ▼
    ┌───────────────┐              ┌───────────────┐
    │ SessionRunner │              │  Dispatcher   │
    │   (BGP FSM)   │              │  (connection  │
    │               │              │   acceptor)   │
    └───────────────┘              └───────────────┘
           │                               │
           │ initiate_connection()         │ accept()
           ▼                               ▼
    ┌──────────────────────────────────────────┐
    │     TCP Connection (over link-local)     │
    └──────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Purpose | Cardinality |
|-----------|---------|-------------|
| **NdpManager** | Top-level manager for all unnumbered interfaces | 1 per daemon |
| **InterfaceNdpManager** | Per-interface NDP discovery (tx/rx loops) | 1 per unnumbered interface |
| **UnnumberedManagerNdp** | Bridge between NDP and BGP, maintains scope_id mappings | 1 per daemon |
| **SessionRunner (FSM)** | BGP state machine, queries NDP for peer discovery | 1 per unnumbered peer |
| **Dispatcher** | Accepts incoming connections, uses scope_id to route to correct FSM | 1 per listening address |

---

## NDP Integration

### NDP Protocol Overview

NDP (RFC 4861) is the IPv6 equivalent of ARP. For BGP unnumbered, we use:
- **Router Solicitation (RS)**: "Is there a router on this link?"
- **Router Advertisement (RA)**: "I'm a router at fe80::X"

### NdpManager Architecture

**NdpManager** manages multiple interfaces:
```rust
pub struct NdpManager {
    interfaces: RwLock<Vec<Arc<InterfaceNdpManager>>>,
    log: Logger,
}
```

**InterfaceNdpManager** handles per-interface discovery:
```rust
pub struct InterfaceNdpManager {
    _tx_thread: Arc<ManagedThread>,  // Sends RA/RS every 5s
    _rx_thread: Arc<ManagedThread>,  // Receives RA/RS
    inner: InterfaceNdpManagerInner,
}
```

**Key Design**: ManagedThread typestate pattern ensures:
- Threads can't be started twice (Ready → Running transition)
- Automatic shutdown signaling (Arc<AtomicBool>)
- Clean thread join on drop (deterministic cleanup)

**NDP Cache**: Single-entry cache per interface
```rust
neighbor_router: Arc<Mutex<Option<ReceivedAdvertisement>>>
```

Only the most recently received RA is kept. Expiry is checked based on time since reception and router lifetime from the RA message.

### UnnumberedManagerNdp: The Bridge

Connects NDP discovery with BGP session management:

```rust
pub struct UnnumberedManagerNdp {
    routers: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    ndp_mgr: Arc<NdpManager>,
    interface_scope_map: Mutex<HashMap<u32, String>>,  // scope_id → interface
    log: Logger,
}
```

**Key Operations**:

1. **add_neighbor**: Start NDP discovery and create BGP session
2. **get_neighbor_for_interface**: Query discovered peer (used by FSM for connection attempts)
3. **get_interface_for_scope**: Map scope_id → interface (used by Dispatcher for routing incoming connections)

**Critical Detail**: scope_id is the interface index, used to disambiguate link-local addresses:
- `fe80::1%2` (scope_id=2, eth0) ≠ `fe80::1%3` (scope_id=3, eth1)
- Without scope_id, the same link-local IP would be ambiguous

---

## BGP FSM Integration

### PeerId: Unified Session Indexing

**Problem**: How do we index sessions when some use IP addresses and others use interface names?

**Solution**: PeerId enum
```rust
pub enum PeerId {
    Ip(IpAddr),          // Numbered peers: "192.0.2.1"
    Interface(String),   // Unnumbered peers: "eth0"
}
```

**Why this works**:
- Unnumbered sessions are indexed by **interface name** (stable)
- Not indexed by **link-local IP** (dynamic, discovered via NDP)
- Dispatcher maps incoming scope_id → interface → SessionRunner

### Persistent FSM Design

**Design Philosophy**: Unnumbered sessions behave like numbered sessions.

**Key Change from Initial Implementation**:
- **Before**: Session created only when NDP discovers peer (one-shot)
- **After**: Session created when peer is configured (persistent)

**Why This Matters**:
1. **Consistency**: Unnumbered sessions have the same lifecycle as numbered sessions
2. **Testability**: Can test FSM without real NDP (use UnnumberedManagerMock)
3. **Resilience**: Session persists through NDP neighbor changes
4. **RFC Compliance**: FSM state transitions follow RFC 4271, not NDP events

### Connection Initiation

FSM queries unnumbered manager for current peer address during connection attempts:

```rust
fn initiate_connection(&self) -> Result<(), Error> {
    let peer_addr = if let Some(unnumbered_mgr) = &self.unnumbered_manager {
        match unnumbered_mgr.get_neighbor_for_interface(interface) {
            Ok(Some(addr)) => addr,
            Ok(None) => {
                // No NDP neighbor discovered yet
                // Treat as async connection failure
                // FSM will cycle back to Idle on ConnectRetryTimer
                return Ok(());
            }
            Err(e) => {
                error!(self.log, "NDP query failed: {}", e);
                return Ok(());
            }
        }
    } else {
        self.peer_config.host  // Numbered peer
    };

    // Proceed with connection attempt
}
```

**Behavior**:
- **NDP peer discovered**: Attempt connection to link-local address
- **No NDP peer**: Silent failure, FSM retries on timer
- Maintains RFC 4271 compliance (connection failures are transparent)

### Connection Acceptance: Dispatcher Routing

**Problem**: Incoming connection has link-local source address. How do we route it to the correct FSM?

**Solution**: Use scope_id from SocketAddrV6 to look up interface name:

```rust
// Dispatcher accepts connection
let peer_addr: SocketAddrV6 = accepted_connection.peer_addr();
let scope_id = peer_addr.scope_id();  // Interface index

// Query unnumbered manager
if let Some(interface) = unnumbered_mgr.get_interface_for_scope(scope_id) {
    let key = PeerId::Interface(interface);

    // Look up session by interface name
    if let Some(session_endpoint) = peer_to_session.get(&key) {
        session_endpoint.event_tx.send(FsmEvent::BgpOpen(connection, peer_addr));
    }
}
```

**Flow**:
```
Accept connection from fe80::2%3
  │
  ├─ Extract scope_id = 3
  ├─ Query: get_interface_for_scope(3) → "eth1"
  ├─ Lookup: peer_to_session[PeerId::Interface("eth1")]
  └─ Route connection to SessionRunner for eth1
```

### Peer Validation

FSM validates incoming connection source matches NDP-discovered peer:
- **Security**: Only accept connections from NDP-discovered peers
- **Collision detection**: Existing connection + new connection from same IP = collision
- **Session stability**: Ignore connections from expired/changed peers

---

## Key Design Decisions

### 1. Persistent FSM, Not Event-Driven

**Decision**: Create FSM when peer is configured, not when NDP discovers peer.

**Rationale**:
- FSM lifecycle matches numbered sessions (consistency)
- FSM controls its own state transitions (proper state machine)
- Session configuration persists even if NDP peer expires
- Testable with mock UnnumberedManager

**Alternative Rejected**: Create FSM only when NDP discovers peer
- Problem: Peer expiry destroys FSM, losing session state
- Problem: NDP events driving FSM violates state machine principles

### 2. Interface Name as Session Key

**Decision**: Index sessions by `PeerId::Interface(String)`, not `PeerId::Ip(IpAddr)`.

**Rationale**:
- Interface name is **stable** (doesn't change when peer expires/changes)
- Link-local IP is **dynamic** (discovered via NDP)
- Enables session persistence through NDP changes
- Supports same link-local IP on multiple interfaces (disambiguated by interface name)

### 3. Nexthop Interface in Path

**Decision**: Add `nexthop_interface: Option<String>` to `Path` struct.

**Rationale**:
- BGP is source of truth for nexthop + interface binding
- Allows same link-local nexthop on multiple interfaces
- Lower-half (mg-lower) gets complete nexthop information
- Survives NDP neighbor changes (stored in RIB)

**Path Structure**:
```rust
pub struct Path {
    pub nexthop: IpAddr,

    /// Interface binding for nexthop resolution.
    /// Only populated for BGP unnumbered sessions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[schemars(skip)]  // Hidden from OpenAPI for backwards compat
    pub nexthop_interface: Option<String>,

    pub bgp: Option<BgpPathProperties>,
    // ...
}
```

**Example**:
```rust
// Route via unnumbered peer on eth0
Path {
    nexthop: IpAddr::V6(fe80::2),
    nexthop_interface: Some("eth0".to_string()),
    // ...
}
```

### 4. UnnumberedManager Trait for Testability

**Decision**: Define `UnnumberedManager` trait with two implementations:
- `UnnumberedManagerNdp`: Production (real NDP)
- `UnnumberedManagerMock`: Testing (simulated NDP)

**Benefits**:
- BGP tests don't require real network interfaces
- Tests can control NDP state changes explicitly
- Tests verify FSM behavior independent of NDP implementation

### 5. ManagedThread Typestate Pattern

**Decision**: Use typestate pattern for thread lifecycle management.

**Benefits**:
- **Type safety**: Can't start thread twice (Ready → Running is one-way)
- **Automatic cleanup**: Drop sets flag and joins thread
- **No leaks**: Thread always joined when ManagedThread is dropped
- **Explicit lifecycle**: State transitions are visible in types

---

## References

### RFCs

- **RFC 4271**: A Border Gateway Protocol 4 (BGP-4)
- **RFC 4861**: Neighbor Discovery for IP version 6 (IPv6)
- **RFC 5549**: Advertising IPv4 Network Layer Reachability Information with an IPv6 Next Hop
- **RFC 8950**: Advertising IPv4 NLRI with an IPv6 Next Hop (BGP IPv4 over IPv6)

### Related Documentation

- [BGP Architecture Guide](bgp-architecture.md) - BGP FSM implementation details
- [README.md](../README.md) - Maghemite overview
- [OpenAPI Specification](../openapi/mg-admin/mg-admin-latest.json) - REST API reference

### Glossary

- **BGP Unnumbered**: BGP peering over IPv6 link-local addresses without global IPs
- **Link-Local Address**: IPv6 address (fe80::/10) valid only on a specific link
- **scope_id**: Interface index disambiguating link-local addresses (e.g., %eth0)
- **NDP**: Neighbor Discovery Protocol (RFC 4861), IPv6 equivalent of ARP
- **Router Advertisement (RA)**: ICMPv6 message announcing router presence on a link
- **Router Solicitation (RS)**: ICMPv6 message requesting router advertisements
- **PeerId**: Session key, either IP address (numbered) or interface name (unnumbered)
- **Path**: Route representation in RIB, includes nexthop and optional interface
- **ManagedThread**: Typestate pattern for thread lifecycle management
- **UnnumberedManager**: Trait abstracting NDP queries for FSM
- **Persistent FSM**: Session created at config time, not discovery time

---

**End of Document**
