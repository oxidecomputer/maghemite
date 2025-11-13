# BGP Implementation Architecture Guide

**Author**: Generated Documentation
**Last Updated**: 2025-10-30
**Audience**: Developers working on or integrating with Maghemite's BGP implementation

---

## Table of Contents

1. [Overview](#overview)
2. [Core Types and Cardinality](#core-types-and-cardinality)
3. [Key Architectural Patterns](#key-architectural-patterns)
4. [Interaction Flows](#interaction-flows)
5. [Single-FSM Collision Handling](#single-fsm-collision-handling)
6. [BgpConnection Trait Deep Dive](#bgpconnection-trait-deep-dive)
7. [Threading and Concurrency Model](#threading-and-concurrency-model)
8. [Quick Reference](#quick-reference)

---

## Overview

Maghemite's BGP implementation follows a **single-FSM-per-peer architecture** using thread-based concurrency. The design emphasizes:

- **Simplicity**: One FSM per configured peer, not dual-FSM (one per direction)
- **Type safety**: Generic over connection type via `BgpConnection` trait
- **Testability**: Abstract connections allow both TCP (production) and channels (testing)
- **RFC compliance**: Implements BGP-4 (RFC 4271) with deterministic collision resolution

### High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         BgpContext                              │
│  ┌──────────────────┐      ┌─────────────────────────────┐      │
│  │ router: Map      │      │ addr_to_session: Map        │      │
│  │ ASN → Router     │      │ IpAddr → SessionEndpoint    │      │
│  └──────────────────┘      └─────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
           │                               │
           │                               │ (shared reference)
           ▼                               ▼
    ┌──────────────┐              ┌───────────────┐
    │   Router     │              │  Dispatcher   │
    │   (1 per     │              │  (1 global    │
    │    ASN)      │              │   listener)   │
    └──────────────┘              └───────────────┘
           │                               │
           │ manages                       │ hands off to
           ▼                               ▼
    ┌──────────────┐              ┌───────────────┐
    │SessionRunner │◄─────────────│  Connection   │
    │(1 per peer)  │   events     │  (0-2 per     │
    └──────────────┘              │   peer)       │
           │                      └───────────────┘
           │ owns                         │
           ▼                              │
    ┌──────────────┐                      │
    │ Connection   │◄─────────────────────┘
    │  Registry    │
    └──────────────┘
```

---

## Core Types and Cardinality

Understanding **how many instances** of each type exist is critical for reasoning about resource usage and concurrency.

### BgpContext

**Purpose**: Top-level management container for all BGP routers in the daemon.

**Cardinality**: **1 per MGD daemon instance** (singleton)

**Location**: `mgd/src/bgp_admin.rs`

**Structure**:
```rust
pub struct BgpContext {
    router: Arc<Mutex<BTreeMap<u32, Arc<Router<BgpConnectionTcp>>>>>,
    addr_to_session: Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<BgpConnectionTcp>>>>
}
```

**Key Fields**:
- `router`: Map of ASN → Router instances (supports multiple BGP speakers)
- `addr_to_session`: **Global routing table** mapping peer IPs to their FSM event channels

**Lifecycle**: Created at daemon startup, lives for the entire daemon lifetime.

**Responsibilities**:
- Managing multiple Router instances (typically just one, but supports multi-ASN)
- Maintaining the global `addr_to_session` lookup table
- Exposing admin API endpoints for configuration

---

### Router<Cnx>

**Purpose**: Represents a single BGP speaker with a specific ASN and Router-ID.

**Cardinality**: **1 per ASN** (typically 1 per daemon, but architecture supports multiple)

**Location**: `bgp/src/router.rs`

**Structure**:
```rust
pub struct Router<Cnx: BgpConnection> {
    pub db: Db,                                    // RIB database handle
    pub config: RouterConfig,                      // Static config (ASN, Router-ID)
    pub sessions: Mutex<BTreeMap<IpAddr, Arc<SessionRunner<Cnx>>>>,
    pub policy: Policy,                            // Compiled Rhai policy programs
    log: Logger,
    shutdown: AtomicBool,
    graceful_shutdown: AtomicBool,
    addr_to_session: Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>>,
    fanout: Arc<RwLock<Fanout<Cnx>>>,             // Update distribution
}
```

**Key Fields**:
- `db`: Reference to centralized RIB (shared with DDM, BFD, static routes)
- `sessions`: Map of peer IP → SessionRunner for all configured peers
- `addr_to_session`: Shared reference to global routing table (see pattern below)
- `fanout`: Distributes route announcements to all established peers

**Lifecycle**:
- Created when BGP router is configured via admin API
- Destroyed when router is deleted or daemon shuts down

**Responsibilities**:
- Managing multiple peer sessions
- Originating routes into RIB (`db.create_origin4()`, `db.create_origin6()`)
- Distributing updates to all peers via fanout mechanism
- Applying import/export policy (shaper/checker programs)
- Coordinating graceful shutdown across all sessions

---

### SessionRunner<Cnx>

**Purpose**: Implements the BGP Finite State Machine (FSM) for one peer relationship.

**Cardinality**: **1 per configured BGP peer** (identified by peer IP address)

**Location**: `bgp/src/session.rs`

**Structure**:
```rust
pub struct SessionRunner<Cnx: BgpConnection> {
    event_tx: Sender<FsmEvent<Cnx>>,              // Send events to self
    event_rx: Receiver<FsmEvent<Cnx>>,            // Receive events
    neighbor: NeighborInfo,                        // Peer IP, name
    session: Arc<Mutex<SessionInfo>>,              // Config/policy for this peer
    clock: Arc<SessionClock>,                      // Session-level timers
    state: Arc<Mutex<FsmStateKind>>,               // Current FSM state
    connections: Arc<Mutex<BTreeMap<ConnectionId, Cnx>>>,  // Connection registry
    primary: Arc<Mutex<Option<ConnectionKind<Cnx>>>>,      // Primary connection
    connector_handle: Mutex<Option<JoinHandle<()>>>,       // Outbound connector thread
    db: Db,                                        // RIB reference
    fanout: Arc<RwLock<Fanout<Cnx>>>,             // Update distribution
    router: Arc<Router<Cnx>>,                      // Parent router reference
    counters: Arc<SessionCounters>,                // Statistics (msgs sent/rcvd)
    message_history: Arc<Mutex<MessageHistory>>,   // Last 1024 messages
    // ... additional fields
}
```

**Key Fields**:
- `event_tx` / `event_rx`: **Channel for FSM events** (timers, connection events, BGP messages)
- `state`: Current FSM state (Idle, Connect, OpenSent, OpenConfirm, Established, etc.)
- `connections`: **Registry of all active connections** (handles collision scenarios)
- `primary`: **The "main" connection** used for queries (may differ during collision)
- `clock`: Session-level timers (ConnectRetryTimer, IdleHoldTimer)

**Lifecycle**:
- Created when peer is configured via `Router::new_session()` or `Router::ensure_session()`
- **Runs in dedicated thread** spawned by `Router::run()` or `Router::new_session()`
- Terminated when peer is deleted or router shuts down

**Threading**: **Each SessionRunner runs in its own thread** executing the `fsm_start()` event loop.

**Responsibilities**:
- Running FSM loop through all BGP states (RFC 4271 §8)
- Managing connection attempts and retries via ConnectRetryTimer
- Handling collision detection and resolution
- Processing BGP messages (Open, Keepalive, Update, Notification, Route-Refresh)
- Managing the connection registry and primary connection tracking
- Sending keepalives and monitoring peer liveness via HoldTimer

---

### Dispatcher<Cnx>

**Purpose**: Accepts inbound BGP connections and hands them off to the appropriate SessionRunner.

**Cardinality**: **1 per daemon** (global listener on port 179)

**Location**: `bgp/src/dispatcher.rs`

**Structure**:
```rust
pub struct Dispatcher<Cnx: BgpConnection> {
    addr_to_session: Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>>,
    shutdown: AtomicBool,
    listen: String,         // Listen address (e.g., "[::]:179")
    log: Logger,
}
```

**Key Fields**:
- `addr_to_session`: Shared reference to global routing table (lookup peer by IP)
- `listen`: Bind address for TCP listener

**Lifecycle**: Created at daemon startup, runs in dedicated thread via `Dispatcher::run()`.

**Threading**: **Runs in its own thread**, continuously accepting connections.

**Responsibilities**:
- Binding to BGP port (typically 179)
- Accepting incoming TCP connections
- Looking up peer in `addr_to_session` map by remote IP
- Applying connection policy (MD5 signature, TTL security)
- Handing off connections by sending `TcpConnectionAcked` event to the appropriate SessionRunner's event channel
- Rejecting connections from unconfigured peers

---

### BgpConnection Trait

**Purpose**: Abstraction over different transport mechanisms (TCP, in-memory channels).

**Location**: `bgp/src/connection.rs`

**Key Methods**:
```rust
pub trait BgpConnection: Send + Clone {
    type Connector: BgpConnector<Self>;

    fn send(&self, msg: Message) -> Result<(), Error>;
    fn peer(&self) -> SocketAddr;
    fn local(&self) -> SocketAddr;
    fn direction(&self) -> ConnectionDirection; // Inbound or Outbound
    fn id(&self) -> &ConnectionId;              // Unique connection identifier
    fn clock(&self) -> &ConnectionClock;        // Per-connection timers
    fn start_recv_loop(&self);                  // Spawns receive thread
}
```

**Implementations**:
- **`BgpConnectionTcp`**: Production TCP-based connections (see below)
- **`BgpConnectionChannel`**: Test-only in-memory channels (see below)

**Why This Abstraction?**
- **Production**: Use real TCP sockets with MD5, TTL, network I/O
- **Testing**: Use fast in-memory channels without TCP overhead or OS resources
- **Type Safety**: Generic `<Cnx: BgpConnection>` ensures compile-time correctness

---

### BgpConnectionTcp

**Purpose**: Production TCP implementation of `BgpConnection`.

**Cardinality**: **0-2 per peer** during normal operation:
- **Usually 1** active connection in Established state
- **Temporarily 2** during collision detection (until resolved)

**Location**: `bgp/src/connection_tcp.rs`

**Structure**:
```rust
pub struct BgpConnectionTcp {
    id: ConnectionId,                      // Unique ID (UUID + addresses)
    peer: SocketAddr,                      // Remote address
    source: SocketAddr,                    // Local address
    conn: Arc<Mutex<TcpStream>>,           // TCP socket
    dropped: Arc<AtomicBool>,              // Shutdown flag
    log: Logger,
    direction: ConnectionDirection,        // Dispatcher or Connector
    connection_clock: ConnectionClock,     // Hold/Keepalive/DelayOpen timers
    recv_loop_params: Mutex<Option<RecvLoopParams>>,  // Parameters for recv thread
    recv_loop_started: AtomicBool,         // Idempotent start flag
}
```

**Key Fields**:
- `conn`: Wrapped TCP socket (Arc<Mutex> for shared ownership and thread-safety)
- `direction`: Records whether connection was initiated by peer (inbound) or the local system (outbound)
- `connection_clock`: Per-connection timers that expire and send FSM events

**Lifecycle**:
1. Created by `BgpConnectorTcp::connect()` (outbound) or `BgpListenerTcp::accept()` (inbound)
2. Registered with SessionRunner via `register_conn()`
3. Receive loop started via `start_recv_loop()` before cloning connection
4. Destroyed when dropped (Arc refcount reaches 0)

**Threading**: **Each connection spawns its own receive loop thread** via `spawn_recv_loop()`. This thread continuously reads from the TCP socket and sends received messages as FSM events.

---

### BgpConnector Trait

**Purpose**: Initiates outbound connections to peers.

**Location**: `bgp/src/connection.rs`

**Key Method**:
```rust
pub trait BgpConnector<Cnx: BgpConnection> {
    fn connect(
        peer: SocketAddr,
        timeout: Duration,
        log: Logger,
        event_tx: Sender<FsmEvent<Cnx>>,
        config: SessionInfo,
    ) -> Result<std::thread::JoinHandle<()>, Error>;
}
```

**Implementation (`BgpConnectorTcp`)**:
- **Spawns background thread** for connection attempt
- Applies MD5 signature and TTL policy **before** connecting
- On success: sends `TcpConnectionConfirmed` event to SessionRunner
- On failure: logs error (FSM ConnectRetryTimer handles automatic retry)

**Cardinality**: No persistent instance; creates a thread per connection attempt.

---

## Key Architectural Patterns

### The addr_to_session Paradigm

**What it is**: A shared lookup table mapping peer IP addresses to their FSM event channels.

**Type**:
```rust
Arc<Mutex<BTreeMap<IpAddr, SessionEndpoint<Cnx>>>>
```

**SessionEndpoint Structure**:
```rust
pub struct SessionEndpoint<Cnx: BgpConnection> {
    pub event_tx: Sender<FsmEvent<Cnx>>,      // FSM event channel
    pub config: Arc<Mutex<SessionInfo>>,      // Session config/policy
}
```

**Why it exists**:
1. **Enables Dispatcher to hand off inbound connections** to the correct SessionRunner without coupling
2. **Enables per-peer policy application** (MD5 keys, TTL, remote ASN checks) by the Dispatcher
3. **Shared between Router, Dispatcher, and BgpContext** for coordinated management

**How it works**:
1. When a peer is configured, Router inserts an entry with the SessionRunner's event channel
2. Dispatcher accepts a connection, looks up the peer IP, and sends a `TcpConnectionAcked` event
3. SessionRunner processes the event and transitions its FSM accordingly

**Benefits**:
- **Decoupling**: Dispatcher doesn't need to know about Router or SessionRunner internals
- **Centralized lookup**: Single source of truth for "is this peer configured?"
- **Thread-safe**: Mutex protection allows concurrent access from Dispatcher and Router

### Diagram: addr_to_session Flow

```
    ┌─────────────┐
    │  Dispatcher │  (accepting connections on port 179)
    └─────────────┘
           │
           │ 1. Accept TCP connection from 10.0.0.2
           │
           ▼
    ┌──────────────────────────────────┐
    │ addr_to_session.get("10.0.0.2")  │
    └──────────────────────────────────┘
           │
           │ 2. Found SessionEndpoint{event_tx, config}
           │
           ▼
    ┌────────────────────────────────────┐
    │ event_tx.send(TcpConnectionAcked)  │
    └────────────────────────────────────┘
           │
           │ 3. Event delivered
           │
           ▼
    ┌─────────────────┐
    │ SessionRunner   │ (for peer 10.0.0.2)
    │ FSM event loop  │
    └─────────────────┘
```

---

### Connection Registry vs Primary Connection

SessionRunner tracks connections using two structures:

**Connection Registry**: `Arc<Mutex<BTreeMap<ConnectionId, Cnx>>>`
- **Purpose**: Tracks ALL active connections by unique ConnectionId
- **Use case**: Handles collision scenarios where 2 connections exist temporarily
- **Lifecycle**: Connections inserted via `register_conn()`, removed when dropped or closed

**Primary Connection**: `Arc<Mutex<Option<ConnectionKind<Cnx>>>>`
- **Purpose**: Tracks the "main" connection for state queries and operations
- **Use case**: Provides single source of truth for "what connection should I use?"
- **Lifecycle**: Updated when first connection registered, or when collision is resolved

**Why both?**
- **Registry handles collision complexity**: During collision, registry has 2 entries
- **Primary provides simplicity**: Query code uses primary, not registry
- **Clean abstraction**: Registry is implementation detail, primary is public interface

**Example Scenario** (Collision):
```
Time 0: Outbound connection initiated
  registry: {conn_1}
  primary: Some(conn_1)

Time 1: Inbound connection arrives (collision!)
  registry: {conn_1, conn_2}
  primary: Some(conn_1)  (unchanged during resolution)

Time 2: Collision resolved, keep conn_2, close conn_1
  registry: {conn_2}
  primary: Some(conn_2)  (updated after resolution)
```

---

### Threading Model Summary

**Per MGD daemon instance with 3 configured peers**:

| Component | Thread Count | Purpose |
|-----------|--------------|---------|
| Dispatcher | 1 | Accept inbound connections |
| SessionRunner | 3 (1 per peer) | FSM event loop |
| Connector | 0-3 | Outbound connection attempts (temporary) |
| Receive Loop | 0-6 (0-2 per peer) | Read from TCP sockets (can be 2 during collision) |
| Connection Timers | Multiple | Send timer expiration events |

**Total active threads during normal operation**: ~10-15 threads for 3 peers.

**Key Characteristics**:
- **No async/await**: Pure thread-based concurrency using `std::thread`
- **Message passing**: FSM events sent via `std::sync::mpsc` channels
- **Shared state**: Protected by `Mutex` and `RwLock`
- **Timer model**: Separate timer threads send events when timers expire

---

## Interaction Flows

### Flow 1: Peer Configuration

**Trigger**: Admin API call to configure new BGP peer.

```
┌─────────┐
│Admin API│
└────┬────┘
     │
     ▼
┌──────────────────────────────────────────┐
│ Router::new_session(peer_addr, config)   │
└──────────────────────────────────────────┘
     │
     ├─► 1. Create SessionRunner instance
     │
     ├─► 2. Insert into Router.sessions map
     │      (Key: peer IP, Value: Arc<SessionRunner>)
     │
     ├─► 3. Insert into addr_to_session map
     │      (Key: peer IP, Value: SessionEndpoint with event_tx)
     │
     └─► 4. spawn(SessionRunner::fsm_start)
            │
            ▼
         ┌────────────────────────┐
         │ FSM loop starts in     │
         │ Idle state             │
         └────────────────────────┘
```

**Key Points**:
- SessionRunner is immediately added to `addr_to_session`, so inbound connections can arrive before we connect
- FSM starts in Idle state, then transitions to Connect when appropriate

---

### Flow 2: Outbound Connection Establishment

**Trigger**: IdleHoldTimerExpires, ManualStart or Reset (Idle), or ConnectRetryTimerExpires (Connect or Active).

**Note**: Outbound connections are only initiated if the peer is **not configured with passive TCP establishment**. If passive mode is enabled, the SessionRunner stays in Active state awaiting inbound connections only.

```
┌────────────────┐
│ SessionRunner  │ (in Idle, Connect, or Active state)
└───────┬────────┘
        │
        │ IdleHoldTimerExpires / ManualStart / Reset
        │ ConnectRetryTimerExpires
        │
        ▼
┌──────────────────────────────┐
│ initiate_connection()        │
│ (skip if passive mode)       │
└──────────────────────────────┘
        │
        ▼
┌────────────────────────────────────┐
│ BgpConnectorTcp::connect()         │
│   - Spawns connector thread        │
└────────────────────────────────────┘
        │
        │ (in connector thread)
        │
        ▼
┌───────────────────────────────────┐
│ 1. Establish TCP connection       │
│ 2. Apply MD5 signature policy     │
│ 3. Apply TTL security policy      │
└───────────────────────────────────┘
        │
        ├─► Success: Send TcpConnectionConfirmed event
        └─► Failure: Log error, FSM will retry

        │ (back in SessionRunner thread)
        │
        ▼
┌──────────────────────────────────┐
│ SessionRunner receives event     │
└──────────────────────────────────┘
        │
        ├─► Send BGP Open message
        │
        ├─► register_conn(connection):
        │     - Start receive loop (spawns thread)
        │     - Insert into connections registry
        │     - Set as primary if none exists
        │
        └─► Transition to OpenSent state
```

**Key Points**:
- Connection attempts can originate from **Idle, Connect, or Active** states
- **Passive TCP establishment**: If configured, peer stays in **Active** and waits for inbound only (no outbound attempts)
- Connector thread is **temporary** and terminates after connection succeeds/fails
- Receive loop thread is **persistent** and lives until connection is closed
- SessionRunner **doesn't block** waiting for connection; uses event-driven model

---

### Flow 3: Inbound Connection Acceptance

**Trigger**: Remote peer initiates TCP connection to our port 179.

```
┌────────────┐
│ Dispatcher │ (listening on port 179)
└──────┬─────┘
       │
       │ TCP SYN from 10.0.0.2
       │
       ▼
┌───────────────────────────────────┐
│ BgpListenerTcp::accept()          │
│   - TCP accept()                  │
└───────────────────────────────────┘
       │
       ▼
┌────────────────────────────────────┐
│ addr_to_session.get("10.0.0.2")    │
└────────────────────────────────────┘
       │
       ├─► Not found? Drop connection
       │
       └─► Found? Continue
           │
           ▼
┌─────────────────────────────────────┐
│ BgpListener::apply_policy()         │
│   - Verify MD5 signature            │
│   - Verify TTL if configured        │
│   - Validate remote ASN             │
└─────────────────────────────────────┘
       │
       ├─► Policy violation? Close with Notification
       │
       └─► Policy OK? Continue
           │
           ▼
┌──────────────────────────────────────┐
│ event_tx.send(TcpConnectionAcked)    │
└──────────────────────────────────────┘
       │
       │ (switch to SessionRunner thread)
       │
       ▼
┌──────────────────────────────────┐
│ SessionRunner receives event     │
└──────────────────────────────────┘
       │
       ├─► Send BGP Open message
       │
       ├─► register_conn(connection):
       │     - Start receive loop (spawns thread)
       │     - Insert into connections registry
       │     - Set as primary if none exists
       │
       └─► Transition state (depends on current state)
```

**Key Points**:
- Dispatcher enforces policy **before** sending event to SessionRunner
- Policy checks use `SessionInfo` from `addr_to_session` entry
- After acceptance, flow is identical to outbound connection

---

### Flow 4: BGP Message Exchange (Established State)

**Trigger**: Connection established, Open messages exchanged.

```
┌────────────────┐          ┌──────────────────┐
│ SessionRunner  │          │ Receive Loop     │
│ (main thread)  │          │ (per-connection  │
│                │          │  thread)         │
└────────┬───────┘          └────────┬─────────┘
         │                           │
         │                           │ Reading from TCP socket
         │                           │
         │                           ▼
         │                  ┌─────────────────────┐
         │                  │ Receive BGP message │
         │                  └─────────────────────┘
         │                           │
         │                           │ Parse message
         │                           │
         │                           ▼
         │                  ┌────────────────────────┐
         │  ◄───────────────│ event_tx.send(         │
         │                  │   BgpMessageReceived   │
         │                  │ )                      │
         │                  └────────────────────────┘
         │
         ▼
┌────────────────────────────┐
│ handle_message() based on  │
│ message type:              │
│  - Keepalive: reset Hold   │
│  - Update: import to RIB   │
│  - Notification: close     │
│  - Route-Refresh: resend   │
└────────────────────────────┘
```

**Keepalive Timer Flow**:
```
┌──────────────────┐
│ Connection Clock │ (KeepaliveTimer)
└────────┬─────────┘
         │
         │ Timer expires
         │
         ▼
┌────────────────────────────────┐
│ event_tx.send(                 │
│   KeepaliveTimerExpired        │
│ )                              │
└────────────────────────────────┘
         │
         ▼
┌────────────────────────────┐
│ SessionRunner:             │
│  - Send Keepalive message  │
│  - Restart KeepaliveTimer  │
└────────────────────────────┘
```

---

## Single-FSM Collision Handling

### Background: Why Single-FSM?

RFC 4271 describes BGP collision detection but doesn't mandate implementation approach. Historically, implementations used two models:

1. **Dual-FSM Model** (used by FRR):
   - One FSM per configured peer
   - **Plus** one FSM per inbound connection
   - Requires inter-FSM communication and synchronization

2. **Single-FSM Model** (used by Maghemite, Cisco):
   - One FSM per configured peer
   - FSM handles **both** outbound and inbound connections
   - Dedicated collision state in FSM

### Advantages of Single-FSM

| Aspect | Single-FSM | Dual-FSM |
|--------|------------|----------|
| **State Management** | One state variable | Multiple state variables + sync |
| **Resource Ownership** | One FSM owns all connections | Unclear ownership during collision |
| **Synchronization** | Internal to FSM | Requires inter-FSM messaging |
| **Testing** | Single control flow to test | Multiple concurrent FSMs to test |
| **Debugging** | One event queue to inspect | Multiple queues to correlate |

**Bottom Line**: Single-FSM is simpler to implement, test, and debug while maintaining full RFC compliance.

---

### Collision Detection

**When does collision occur?**

Collision is detected when SessionRunner receives a new connection event while already having a connection:

| Current State | New Event | Action |
|---------------|-----------|--------|
| OpenSent | TcpConnectionAcked/Confirmed with **different direction** | Enter ConnectionCollision |
| OpenConfirm | TcpConnectionAcked/Confirmed | Enter ConnectionCollision |
| Established | TcpConnectionAcked/Confirmed | **Refuse new connection** (close immediately) |
| Established | Open message on non-Established connection | **Resolve collision** without entering ConnectionCollision state |

**Key Insights**:
- "Different direction" means one connection was initiated by us (outbound) and one was initiated by peer (inbound).
- New connections are **refused** in Established state (not transitioned to ConnectionCollision).
- If an Open is received on an existing connection not owned by the Established FSM state, collision resolution occurs without re-entering ConnectionCollision state.

---

### Collision Resolution Algorithm (RFC 4271 §6.8)

**Simplified Rule**:
- **Lower BGP ID** breaks the tie: lower ID keeps the connection it **received**
- **Higher BGP ID** keeps the connection it **initiated**

**Why this rule?** It ensures both sides reach the same decision deterministically.

---

### Collision State Types

The FSM uses a dedicated state to handle collisions:

```rust
pub enum CollisionPair<Cnx: BgpConnection> {
    // Existing in OpenConfirm, new connection just arrived
    OpenConfirm(PeerConnection<Cnx>, Cnx),

    // Both connections in OpenSent (no peer info from new yet)
    OpenSent(Cnx, Cnx),
}
```

**Why two variants?**

- **OpenConfirm collision**: We already received Open from existing connection (have BGP ID), can resolve immediately
- **OpenSent collision**: Neither connection has received Open yet, must wait for new connection's Open to get remote BGP ID

---

### Collision Handling Flow

**Scenario**: We initiate outbound connection, peer simultaneously initiates inbound connection.

```
Time 0: SessionRunner in Connect state
  └─► ConnectRetryTimer expires
      └─► BgpConnectorTcp::connect() spawns thread
          └─► TcpConnectionConfirmed event sent

Time 1: SessionRunner receives TcpConnectionConfirmed
  ├─► Send Open message
  ├─► register_conn(conn_1) [direction: Outbound]
  └─► Transition to OpenSent(conn_1)

Time 2: Dispatcher accepts inbound connection from peer
  └─► TcpConnectionAcked event sent

Time 3: SessionRunner (in OpenSent) receives TcpConnectionAcked
  ├─► Check: new connection direction (Inbound) != existing (Outbound) ✓
  ├─► register_conn(conn_2) [direction: Inbound]
  └─► Transition to ConnectionCollision(OpenSent(conn_1, conn_2))
      │
      │ Registry now has: {conn_1, conn_2}
      │ Primary still points to: conn_1

Time 4: Receive Open from conn_2 (new connection)
  └─► Now we have remote_bgp_id
      └─► Run collision_resolution()
          ├─► Example: local_bgp_id=100, remote_bgp_id=200
          ├─► 100 < 200, so keep Dispatcher connection (conn_2)
          ├─► Close conn_1 with Cease notification
          └─► Transition to OpenConfirm(conn_2)
              │
              │ Registry now has: {conn_2}
              │ Primary now points to: conn_2

Time 5: Receive Open from conn_2
  └─► Send Keepalive
  └─► Transition to Established
```

**Key Points**:
- Connection registry safely tracks both connections during collision
- Resolution happens once we have both BGP IDs
- Losing connection closed gracefully with Notification (Cease, Connection Collision Resolution)
- Single FSM maintains clean control flow throughout

---

### Deterministic Collision Resolution

**Configuration Option**: `deterministic_collision_resolution`

**Purpose**: Controls collision resolution behavior when a new connection completes while in Established state.

**Default**: `false` (timing-based resolution)

**Behavior**:

When **disabled** (`false`, default):
- **"First to Established wins"** - the existing Established connection is preserved
- New connections that complete are closed unconditionally
- Resolution is timing-based: whichever connection reached Established first survives

When **enabled** (`true`):
- **BGP-ID-based resolution** - collision resolution uses RFC 4271 §6.8 deterministic tie-breaking
- Compares local and remote BGP-IDs to decide which connection to keep
- The Established connection may be closed if BGP-ID comparison favors the new connection
- Resolution is deterministic regardless of timing

**Note**: This is a partial implementation of `CollisionDetectEstablishedState`. A full implementation would involve tracking multiple connections through Established state transitions, which is not believed to be worth the added complexity at this time. See `bgp/src/session.rs` in `fsm_established()` for detailed implementation notes.

---

### When to Enable Deterministic Resolution

In very particular timing scenarios, the FSM on one peer may see its connection reach Established state before collision resolution completes. This can result in both sides sending Notifications to different connections, causing both to shut down.

**Example Scenario**: R1 and R2 simultaneously initiate connections to each other, with R1 having a lower BGP Identifier.

**R1's Perspective** (lower BGP ID):
```
1. R1 initiates outbound connection to R2 (R1 → R2)
2. R1 gets TcpConnectionConfirmed for outbound connection (R1 → R2)
3. R1 sends Open via outbound connection (R1 → R2), moves to OpenSent
4. R1 gets Open from outbound connection (R1 → R2), moves to OpenConfirm
5. R1 gets TcpConnectionAcked for inbound connection (R2 → R1)
6. R1 sends Open via inbound connection (R2 → R1), moves to ConnectionCollision
7. R1 gets Keepalive from outbound connection (R1 → R2), moves to Established
8. R1 gets Open and sends Notification via inbound connection (R2 → R1)
   because Established wins over collision resolution
9. R1 gets Notification from outbound connection (R1 → R2), moves to Idle
```

**R2's Perspective** (higher BGP ID):
```
1. R2 initiates outbound connection to R1 (R2 → R1)
2. R2 gets TcpConnectionAcked for inbound connection from R1 (R1 → R2)
3. R2 sends Open via inbound connection (R1 → R2), moves to OpenSent
4. R2 gets TcpConnectionConfirmed for new outbound connection (R2 → R1),
   moves to ConnectionCollision
5. R2 gets Open from inbound connection (R1 → R2)
6. R2 performs collision resolution, R2 wins with higher BGP ID
7. R2 sends Notification via inbound connection (R1 → R2), moves to OpenSent
8. R2 receives Open via outbound connection (R2 → R1), moves to OpenConfirm
9. R2 receives Notification via inbound connection (R2 → R1), moves to Idle
```

**What Happened**: The timing worked out such that one peer (R1) saw its connection move into Established—which is valid in the dual-FSM model we're emulating—but that connection would have lost the collision resolution tie-breaker. This results in both sides sending a Notification to different connections for different reasons, causing both connections to shut down and restart.

**Solution**: Enable `deterministic_collision_resolution` to ensure BGP-ID-based resolution even when one side reaches Established first. This guarantees both peers agree on which connection to keep, regardless of timing.

**When to enable**:
- Network has frequent simultaneous connection attempts between peers
- Logs show repeated collision-related session resets
- Debugging reveals the race condition described above

---

## BgpConnection Trait Deep Dive

### Purpose of the Abstraction

The `BgpConnection` trait decouples the FSM from the transport layer:

| Aspect | BgpConnectionTcp | BgpConnectionChannel |
|--------|------------------|----------------------|
| **Use Case** | Production | Testing |
| **Transport** | TCP sockets | In-memory channels |
| **Threading** | Spawns receive loop thread | Spawns receive loop thread |
| **OS Resources** | Uses file descriptors | Pure memory |
| **Speed** | Network I/O latency | Instant (in-memory) |
| **Compilation** | Always compiled | `#[cfg(test)]` only |

**Benefits**:
- **Fast tests**: No TCP overhead, no port conflicts, no TIME_WAIT states
- **Isolation**: Tests don't require network access or permissions
- **Type Safety**: Generic `<Cnx: BgpConnection>` ensures FSM works with both

---

### BgpConnectionTcp Implementation Details

**Key Implementation Points**:

1. **Arc<Mutex<TcpStream>>**: Allows shared ownership across threads (receive loop, send calls)

2. **ConnectionClock**: Each connection has independent timers:
   ```rust
   pub struct ConnectionClock {
       hold_timer: Timer,
       keepalive_timer: Timer,
       delay_open_timer: Timer,
   }
   ```
   These timers send FSM events when they expire.

3. **Receive Loop Threading**:
   ```rust
   pub fn start_recv_loop(&self) {
       if self.recv_loop_started.swap(true, Ordering::SeqCst) {
           return;  // Idempotent: only start once
       }

       let params = self.recv_loop_params.lock().unwrap().take().unwrap();
       std::thread::spawn(move || {
           spawn_recv_loop(params);
       });
   }
   ```

   - **Idempotent**: Can safely call multiple times, only spawns once
   - **Ownership**: Thread takes ownership of `RecvLoopParams`
   - **Lifetime**: Thread lives until connection closes or error occurs

4. **Receive Loop Logic**:
   ```rust
   fn spawn_recv_loop(params: RecvLoopParams) {
       loop {
           match read_message(&mut stream) {
               Ok(msg) => {
                   event_tx.send(FsmEvent::BgpMessageReceived(msg)).unwrap();
               }
               Err(e) => {
                   event_tx.send(FsmEvent::TcpConnectionFails).unwrap();
                   break;
               }
           }
       }
   }
   ```

5. **Graceful Shutdown**:
   - `dropped: Arc<AtomicBool>` flag set when connection is dropped
   - Receive loop checks flag and terminates cleanly
   - Prevents "send on closed channel" panics

---

### BgpConnectionChannel Implementation

**Purpose**: Fast testing without TCP overhead.

**Core Concept**: Global in-memory "network" simulates message passing.

#### The Global NET Instance

**Declaration**:
```rust
lazy_static! {
    static ref NET: Network = Network::new();
}

pub struct Network {
    endpoints: Mutex<HashMap<SocketAddr, Sender<(SocketAddr, Endpoint<Message>)>>>,
}
```

**What is it?**
- **Singleton** simulated network shared across all tests
- Maps `SocketAddr` → channel endpoint for that "peer"
- Thread-safe via `Mutex`

**How it works**:

1. **Registration**:
   ```rust
   impl BgpConnectionChannel {
       pub fn new(local: SocketAddr, peer: SocketAddr) -> Self {
           let (tx, rx) = mpsc::channel();
           NET.endpoints.lock().unwrap().insert(local, tx);
           // ... create connection
       }
   }
   ```

2. **Sending**:
   ```rust
   pub fn send(&self, msg: Message) -> Result<(), Error> {
       let peer_tx = NET.endpoints.lock().unwrap().get(&self.peer).cloned();
       peer_tx.unwrap().send((self.local, msg)).unwrap();
       Ok(())
   }
   ```

   Looks up peer's channel and sends message directly.

3. **Receiving**:
   ```rust
   // Receive loop (no separate thread, just polling)
   loop {
       match self.rx.recv() {
           Ok((from, msg)) => {
               event_tx.send(FsmEvent::BgpMessageReceived(msg)).unwrap();
           }
           Err(_) => break,
       }
   }
   ```

**Key Differences from TCP**:
- **Instant delivery**: No network latency simulation (messages pass through in-memory channels)
- **No connection establishment overhead**: "Connected" as soon as created
- **No MD5/TTL**: Policy checks skipped in tests

**Why lazy_static?**
- Tests can create multiple "routers" that communicate via NET
- No need to pass network reference around
- Automatically cleaned up when tests end

---

## Threading and Concurrency Model

### Thread Inventory

**For a daemon with 3 configured BGP peers in Established state**:

| Thread Type | Count | Lifetime | Purpose |
|-------------|-------|----------|---------|
| **Main Thread** | 1 | Daemon lifetime | Admin API, coordination |
| **Dispatcher** | 1 | Daemon lifetime | Accept inbound BGP connections |
| **SessionRunner** | 3 | Per-peer lifetime | FSM event loop (1 per peer) |
| **Receive Loop** | 3 | Per-connection lifetime | Read from TCP socket, send FSM events |
| **Connector** | 0 | Temporary | Outbound connection establishment (only during Connect) |
| **Clock Threads** | 6 | Per-session/connection lifetime | 1 SessionClock per peer, 1 ConnectionClock per connection |

**Total active threads**: ~13 threads for 3 established peers.

**Clock Thread Breakdown**:
- **SessionClock** (1 per SessionRunner): Manages ConnectRetryTimer, IdleHoldTimer
- **ConnectionClock** (1 per BgpConnection): Manages HoldTimer, KeepaliveTimer, DelayOpenTimer

### Thread Safety Mechanisms

**Synchronization Primitives Used**:

1. **Arc<Mutex<T>>**: Shared mutable state
   - `Router.sessions`
   - `Router.addr_to_session`
   - `SessionRunner.connections`
   - `TcpStream` (for concurrent send)

2. **Arc<RwLock<T>>**: Read-heavy shared state
   - `Router.fanout` (many readers during updates, one writer during config)

3. **AtomicBool**: Lock-free flags
   - `Router.shutdown`
   - `BgpConnectionTcp.dropped`
   - `BgpConnectionTcp.recv_loop_started`

4. **mpsc::channel**: Message passing
   - FSM event delivery (timer threads → SessionRunner)
   - BGP message delivery (receive loop → SessionRunner)
   - Dispatcher routing (Dispatcher → SessionRunner)

### Concurrency Patterns

**Pattern 1: Event-Driven FSM**
```
Multiple Event Sources:
  - Clock threads (SessionClock, ConnectionClock)
  - Receive loop (BGP messages)
  - Dispatcher (inbound connections)

All send to: event_rx channel

Single Consumer: SessionRunner thread
  - Processes events sequentially
  - No concurrent state mutation within FSM
```

**Pattern 2: Shared Lookup Table**
```
Writers:
  - Router (inserts/removes peers)

Readers:
  - Dispatcher (looks up peer on inbound connection)
  - Query APIs (lists configured peers)

Protection: Arc<Mutex<BTreeMap<...>>>
```

**Pattern 3: Fanout Distribution**
```
Writer:
  - Router (announces new routes)

Readers:
  - Each SessionRunner (checks policy, sends updates)

Protection: Arc<RwLock<Fanout>>
  - Write lock: Add/remove sessions
  - Read lock: Distribute updates
```

### Avoiding Deadlocks

**Locking Order Rules**:

1. **Never hold multiple locks simultaneously** unless absolutely necessary
2. **Always lock in consistent order**:
   - `Router.sessions` before `SessionRunner.connections`
   - `addr_to_session` before session-specific locks
3. **Release locks before calling callbacks**
4. **Use channels for cross-thread communication** instead of shared locks

**Example - Safe Pattern**:
```rust
// Good: Lock, read, unlock, then use data
let event_tx = {
    let map = addr_to_session.lock().unwrap();
    map.get(&peer_ip).map(|ep| ep.event_tx.clone())
};

if let Some(tx) = event_tx {
    tx.send(event).unwrap();  // No locks held here
}
```

**Example - Unsafe Pattern**:
```rust
// Bad: Holding lock while sending (could deadlock if receiver tries to lock)
let map = addr_to_session.lock().unwrap();
if let Some(ep) = map.get(&peer_ip) {
    ep.event_tx.send(event).unwrap();  // Still holding lock!
}
```

---

## Quick Reference

### Component Cardinality Cheat Sheet

| Component | Cardinality | Per What? | Thread? |
|-----------|-------------|-----------|---------|
| BgpContext | 1 | Daemon | No (state only) |
| Router | 1 | ASN | No (state only) |
| Dispatcher | 1 | Daemon | Yes (accept loop) |
| SessionRunner | 1 | Peer | Yes (FSM loop) |
| BgpConnection | 0-2 | Peer | No (state only) |
| Receive Loop | 1 | Active connection | Yes (read loop) |
| Connector | 0-1 | Connect attempt | Yes (temporary) |
| SessionClock | 1 | SessionRunner | Yes (clock thread) |
| ConnectionClock | 1 | BgpConnection | Yes (clock thread) |

### FSM States Quick Reference

| State | Meaning | Transitions Out |
|-------|---------|-----------------|
| **Idle** | Session disabled or cooling down | → Connect (admin enable or timer) |
| **Connect** | Waiting for connection establishment | → OpenSent (connected) or → Active (failed) |
| **Active** | Retrying connection | → Connect (retry) or → OpenSent (connected) |
| **OpenSent** | Sent Open, waiting for peer's Open | → OpenConfirm (Open rcvd) or → Idle (error) |
| **OpenConfirm** | Open exchanged, waiting for Keepalive | → Established (Keepalive rcvd) |
| **Established** | Fully operational, exchanging routes | → Idle (error/close) |
| **ConnectionCollision** | Two connections exist, resolving | → OpenConfirm/Established (resolved) |

### Defensive Timer Handling

The FSM implements defensive handling for timer events that should be impossible in certain states. Instead of transitioning to Idle (which would unnecessarily reset the session), unexpected timer events are logged with a "BUG:" prefix, the timer is stopped, and the FSM remains in its current state.

**Timer Ownership by State:**

| Timer | Expected States | Unexpected in |
|-------|----------------|---------------|
| **IdleHoldTimer** | Idle only | All other states |
| **ConnectRetryTimer** | Connect, Active | OpenSent, OpenConfirm, ConnectionCollision, Established |
| **DelayOpenTimer** | Connect, Active (if implemented) | OpenSent, OpenConfirm, ConnectionCollision, Established |
| **HoldTimer** | States with connections (OpenSent, OpenConfirm, Established, ConnectionCollision) | Idle, Connect, Active |
| **KeepaliveTimer** | States with connections (OpenSent, OpenConfirm, Established, ConnectionCollision) | Idle, Connect, Active |

**Defensive Behavior:**
```rust
// Example: IdleHoldTimer fires in OpenSent state
SessionEvent::IdleHoldTimerExpires => {
    if !session_timer!(self, idle_hold).enabled() {
        continue;  // Timer already stopped
    }
    session_timer!(self, idle_hold).stop();
    session_log!("BUG: idle hold timer expires event not expected in this state, ignoring");
    continue;  // Stay in OpenSent, don't reset to Idle
}
```

**Rationale:**
- Timer race conditions can occur during state transitions (timer fires after state change)
- Defensive handling prevents false session resets
- "BUG:" prefix in logs indicates investigation-worthy events
- FSM stability is preserved even when timers misbehave

### Event Types Quick Reference

| Event | Source | Meaning |
|-------|--------|---------|
| `TcpConnectionConfirmed` | Connector thread | Outbound connection succeeded |
| `TcpConnectionAcked` | Dispatcher | Inbound connection accepted |
| `Message` | Receive loop | BGP message received (Open, Keepalive, Update, Notification, Route-Refresh) |
| `ConnectRetryTimerExpires` | SessionClock | Time to retry connection |
| `IdleHoldTimerExpires` | SessionClock | Idle hold dampening period expired |
| `HoldTimerExpires` | ConnectionClock | Peer liveness timeout |
| `KeepaliveTimerExpires` | ConnectionClock | Time to send Keepalive |
| `DelayOpenTimerExpires` | ConnectionClock | Time to send delayed Open |

---

## Conclusion

Maghemite's BGP implementation demonstrates a **pragmatic, production-ready architecture**:

✅ **Single-FSM-per-peer** simplifies state management and testing
✅ **addr_to_session pattern** elegantly decouples Dispatcher from SessionRunner
✅ **Connection registry** handles collision complexity transparently
✅ **BgpConnection trait** enables fast testing without TCP overhead
✅ **Thread-per-session model** provides clear isolation and debuggability
✅ **RFC 4271 compliant** with deterministic collision resolution

For new developers:
1. Start by understanding **SessionRunner** (the FSM heart)
2. Trace a connection lifecycle (outbound or inbound) end-to-end
3. Understand **addr_to_session** as the handoff/lookup mechanism
4. Study collision handling in **FsmState::ConnectionCollision**

---

**Questions?** Check the code:
- `bgp/src/session.rs` - SessionRunner and FSM logic
- `bgp/src/router.rs` - Router coordination
- `bgp/src/dispatcher.rs` - Inbound connection acceptance
- `bgp/src/connection_tcp.rs` - TCP connection implementation
- `bgp/src/connection_channel.rs` - Test connection implementation
