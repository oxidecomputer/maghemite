# Generic Unnumbered Interface Manager

**Status**: Design / plan of record
**Last Updated**: 2026-07-29
**Audience**: Developers working on Maghemite's BGP unnumbered and DDM
interface lifecycle management

---

## 1. Motivation

Two Maghemite subsystems run routing protocols exclusively over IPv6
link-local addresses on named interfaces:

- **BGP unnumbered** (mgd): NDP router discovery per interface, feeding
  the BGP FSM. Already has a lifecycle manager
  (`unnumbered::UnnumberedManager`, post-#800) that reconciles *configured*
  interfaces against *available* system interfaces, handling interfaces
  that don't exist yet, link-local addresses that appear/disappear/change,
  and ifindex changes.

- **DDM** (ddmd): one routing state machine (SM) per interface. Today the
  interface set is fixed at process start: SMF's `config/interfaces`
  property is translated by `smf/ddm_method_script.sh` into `-a`
  address-object arguments, `ddmd/src/main.rs::start_state_machines`
  creates one SM per address object, and each SM's Init state polls
  `libnet::get_ipaddr_info` until the address object resolves. There is no
  dynamic add/remove, no reaction to address or ifindex changes after
  init, and every SM holds a frozen fan-out list of every other SM's event
  sender.

DDM needs dynamic add/remove of state machines, keyed by *interface name*
(link-local addresses are not managed by the control plane and may not
exist yet at configuration time). This is exactly the problem the
unnumbered manager already solves for BGP. This design generalizes that
manager so both consumers share the interface/link-local reconciler while
keeping protocol runtimes (NDP router discovery, DDM SMs) out of the
shared core.

## 2. Goals and non-goals

Goals:

- One generic, protocol-neutral interface lifecycle manager
  (`UnnumberedInterfaceManager<F>`) in the `unnumbered` crate, which
  becomes a true leaf crate (no NDP/BGP/DDM/`mg-api-types` deps).
- BGP unnumbered behavior is preserved exactly; only crate/type
  organization changes.
- DDM gains dynamic add/remove of per-interface state machines with
  per-interface configuration, driven through the same manager.
- The design must not obstruct a future migration of either consumer to
  async (tokio) runtimes.

Non-goals / deferred:

- **Dual-protocol exclusion.** An unnumbered interface must not run both
  BGP unnumbered and DDM at the same time. This is a real invariant, but
  *enforcement placement is deferred*: the likely right owner is
  Nexus/control-plane assignment, not maghemite. Maghemite exposes
  configured/active state for observability so violations are visible.
  This is an explicit open review question, not a dismissed requirement.
- Multiple runtimes per interface within one manager. Each manager owns
  its interfaces exclusively; one entry per interface name.

## 3. Architecture overview

```diagram
┌───────────────────────────────────────────────────────────────────┐
│ unnumbered (leaf crate)                                           │
│  ┌──────────────────────────────┐  ┌────────────────────────────┐ │
│  │ UnnumberedInterfaceManager<F>│  │ LifecycleDriver<F> (priv)  │ │
│  │  desired: Map<name, Config>  │  │  owns F by value           │ │
│  │  active:  ActiveMap<F>       │  │  runs on monitor thread    │ │
│  │  configure/unconfigure/query │  │  activate/deactivate here  │ │
│  └──────────────────────────────┘  └────────────────────────────┘ │
│  trait UnnumberedRuntimeFactory { Config, Runtime, Error }        │
└───────────────┬──────────────────────────────────┬────────────────┘
                │                                  │
        ┌───────▼────────┐                 ┌───────▼──────────────┐
        │ ndp crate      │                 │ ddm crate            │
        │ NdpRuntime-    │                 │ DdmRuntimeFactory    │
        │ Factory,       │                 │ DdmInterfaceManager  │
        │ Unnumbered-    │                 │ SmHandle, event hub  │
        │ ManagerNdp     │                 └───────┬──────────────┘
        └───────┬────────┘                         │
                │                          ┌───────▼──────┐
        ┌───────▼────────┐                 │ ddmd         │
        │ mgd            │                 │ constructs   │
        │ BgpUnnumbered- │                 │ manager,     │
        │ ManagerNdp     │                 │ admin API    │
        │ impls bgp::    │                 └──────────────┘
        │ BgpUnnumbered  │
        └───────┬────────┘
                │
        ┌───────▼────────┐
        │ bgp crate      │
        │ trait          │
        │ BgpUnnumbered  │
        │ (consumer port)│
        └────────────────┘
```

Dependency edges after the reorganization:

- `unnumbered` depends on nothing protocol-specific (only
  `network-interface`, `iddqd`, `mg-common`, `slog`).
- `ndp` depends on `unnumbered` (dep direction *flips*; today
  `unnumbered → ndp`). `Ipv6NetworkInterface` moves into `unnumbered`.
- `bgp` owns the `BgpUnnumbered` trait and `BgpUnnumberedInterface`
  struct (its consumer port) and drops its dep on `unnumbered`.
- `mgd` defines `BgpUnnumberedManagerNdp`, a local newtype over
  `Arc<UnnumberedManagerNdp>` implementing `bgp::BgpUnnumbered`. mgd
  already depends on both sides, avoiding a bad `ndp → bgp` edge.
  `mg_api_types` conversions move into mgd.
- `ddm` defines `DdmRuntimeFactory` and `DdmInterfaceManager`.

## 4. The generic manager

### 4.1 Factory trait

The factory is the seam between the generic reconciler and the
protocol-specific runtime:

```rust
/// Implemented by protocol runtimes (NDP router discovery, DDM state
/// machines) that the manager activates on unnumbered interfaces.
///
/// The factory is owned by value by the manager's private lifecycle
/// driver and moved onto the dedicated monitor thread. All callbacks
/// execute on that thread only; `Sync` is therefore not required.
pub trait UnnumberedRuntimeFactory: Send + 'static {
    /// Per-interface configuration recorded as desired state.
    type Config: Clone + PartialEq + Send + 'static;

    /// Opaque handle for an activated runtime. Dropped or consumed by
    /// `deactivate` on the monitor thread.
    type Runtime: Send + 'static;

    /// Activation error, logged and retried on the next sweep.
    type Error: std::fmt::Display;

    /// Start the runtime on an available interface. `ifx` is a snapshot
    /// of (name, link-local address, nonzero scope id).
    fn activate(
        &self,
        ifx: &Ipv6NetworkInterface,
        config: &Self::Config,
    ) -> Result<Self::Runtime, Self::Error>;

    /// Apply a config change to a running runtime. Return `Updated` if
    /// the change was applied in place; return `Restart` (the default)
    /// to have the manager deactivate and reactivate with the new config.
    ///
    /// The previous config is intentionally not passed: the manager's
    /// `ActiveEntry` is its single source of truth and today's
    /// implementors apply `new` unconditionally. A future factory with
    /// mixed hot/restart config fields may want an `old` parameter back
    /// to diff against; that is a cheap workspace-internal change.
    fn reconfigure(
        &self,
        runtime: &Self::Runtime,
        new: &Self::Config,
    ) -> Reconfigure {
        let _ = (runtime, new);
        Reconfigure::Restart
    }

    /// Stop the runtime. Consumes it; the default drops it, which is
    /// sufficient for runtimes whose Drop joins their threads.
    fn deactivate(&self, runtime: Self::Runtime) {
        drop(runtime)
    }
}

pub enum Reconfigure {
    /// Config applied in place; manager updates the recorded config.
    Updated,
    /// Runtime must be restarted with the new config.
    Restart,
}
```

`Ipv6NetworkInterface` (name, `Ipv6Addr`, `NonZeroU32` scope id) moves
from `ndp` into `unnumbered` since the reconciler is its real owner.

### 4.2 Active entry and map

`ActiveEntry<F>` is the generic replacement for today's
`UnnumberedInterface`; the NDP-specific `RouterDiscoveryRuntime` becomes
the `Runtime` payload.

```rust
pub struct ActiveEntry<F: UnnumberedRuntimeFactory> {
    name: String,
    local_address: Ipv6Addr,
    scope_id: NonZeroU32,
    /// Last config applied to the runtime (post-reconfigure).
    config: F::Config,
    runtime: F::Runtime,
}

impl<F: UnnumberedRuntimeFactory> ActiveEntry<F> {
    pub fn name(&self) -> &str;
    pub fn local_address(&self) -> Ipv6Addr;
    pub fn scope_id(&self) -> NonZeroU32;
    pub fn config(&self) -> &F::Config;
    pub fn runtime(&self) -> &F::Runtime;
}

impl<F: UnnumberedRuntimeFactory> BiHashItem for ActiveEntry<F> {
    type K1<'a> = NonZeroU32;   // scope id
    type K2<'a> = &'a str;      // interface name
    ...
}

/// Generic version of today's InterfaceMap; same accessor surface
/// (insert_overwrite, remove_by_name, get_by_scope_id, get_by_name,
/// contains_*, is_empty, iter), parameterized over F.
pub struct ActiveMap<F: UnnumberedRuntimeFactory>(BiHashMap<ActiveEntry<F>>);
```

Notes:

- The scope-id index stays even though DDM doesn't need lookups by scope:
  scope id is already part of runtime identity (a scope change forces a
  restart) and the second index is cheap.
- **In-place reconfigure** mutates the entry via remove-by-name /
  update config / reinsert. Config is not part of either key, so derived
  keys are unaffected; the reinsert asserts that nothing is displaced.

### 4.3 Manager / lifecycle driver split

The public manager holds only shared state and never touches the factory.
The private driver owns the factory *by value* and is moved into the
monitor thread — structurally guaranteeing factory callbacks happen only
there.

```rust
/// State shared between the public manager and the lifecycle driver.
struct Shared<F: UnnumberedRuntimeFactory> {
    log: Logger,
    /// Admin intent: interface name -> desired config. Survives runtime
    /// flaps. Pending = desired minus active.
    desired: Mutex<HashMap<String, F::Config>>,
    /// Interfaces with running runtimes. The authoritative registry.
    active: Mutex<ActiveMap<F>>,
}

pub struct UnnumberedInterfaceManager<F: UnnumberedRuntimeFactory> {
    shared: Arc<Shared<F>>,
    /// Wake channel to the monitor thread. Buffer size 1; a pending
    /// token means the monitor will observe this change too. `None` in
    /// tests, which drive reconciliation manually.
    monitor_tx: Option<SyncSender<()>>,
    /// Joined on drop, after `monitor_tx` is disconnected.
    monitor_thread: Arc<ManagedThread>,
}

/// Private. Owns the factory; runs on the monitor thread.
struct LifecycleDriver<F: UnnumberedRuntimeFactory> {
    log: Logger,
    factory: F,
    shared: Arc<Shared<F>>,
    sweep_interval: Duration,
    wake_rx: Receiver<()>,
}
```

Public API:

```rust
impl<F: UnnumberedRuntimeFactory> UnnumberedInterfaceManager<F> {
    /// Spawns the monitor thread. `sweep_interval` is how often the
    /// driver re-enumerates system interfaces between wakes (mgd keeps
    /// its current ~5s; ddmd derives this from `ip_addr_wait`, ~1s).
    pub fn new(
        factory: F,
        sweep_interval: Duration,
        log: Logger,
    ) -> Arc<Self>;

    /// Record desired state and wake the monitor. Never blocks on
    /// runtime work. Inserting an existing name updates its config.
    pub fn configure(&self, interface: impl AsRef<str>, config: F::Config);

    /// Remove desired state and wake the monitor. Teardown is performed
    /// by the monitor thread, eventually consistent — NOT inline on the
    /// caller's thread (a change from today's UnnumberedManager).
    pub fn unconfigure(&self, interface: impl AsRef<str>);

    // --- synchronous queries; closures must not block or await ---
    pub fn desired(&self) -> Vec<(String, F::Config)>;
    pub fn pending(&self) -> Vec<(String, F::Config)>;   // desired − active
    pub fn active_names(&self) -> Vec<String>;
    pub fn with_active<R>(
        &self,
        interface: &str,
        f: impl FnOnce(&ActiveEntry<F>) -> R,
    ) -> Option<R>;
    pub fn with_active_by_scope<R>(
        &self,
        scope_id: NonZeroU32,
        f: impl FnOnce(&ActiveEntry<F>) -> R,
    ) -> Option<R>;
    pub fn for_each_active(&self, f: impl FnMut(&ActiveEntry<F>));
    pub fn monitor_running(&self) -> bool;
}
```

Driver loop (per pass, same shape as today's
`reconcile_interfaces_with_activator`):

1. Snapshot available interfaces once via `NetworkInterface::show()`
   (getifaddrs-style; single syscall per pass regardless of interface
   count). Keep only IPv6 unicast link-local addresses with nonzero
   index. **Multi-link-local policy**: if an interface has several
   link-local addresses, select the numerically lowest deterministically
   (today's code takes snapshot order and warns). This is a semantic
   change from DDM's explicit address-object selection; called out for
   review.
2. Deactivation pass over `active`, collecting names to deactivate:
   - not in `desired` → deactivate
   - not in `available` → deactivate
   - scope id or link-local changed → deactivate (reactivated in pass 3)
   - config differs from `desired` → call `factory.reconfigure`;
     `Updated` → remove/mutate/reinsert entry with new config;
     `Restart` → deactivate (reactivated in pass 3)
   Deactivations remove the entry under the lock but call
   `factory.deactivate(runtime)` after the lock is released.
3. Activation pass over a snapshot of `desired`: any name that is
   available but not active → `factory.activate`; on success
   `insert_overwrite` (displacement believed unreachable, dropped outside
   the lock); on failure log and leave pending for the next sweep.
4. `wake_rx.recv_timeout(sweep_interval)`:
   - `Ok(())` or `Timeout` → next pass
   - `Disconnected` → **drain**: remove every active entry and
     `factory.deactivate` each on this thread, then exit.

`Drop for UnnumberedInterfaceManager` sets `monitor_tx = None`
(disconnecting the channel) before `ManagedThread`'s field drop joins the
thread — the same ordering trick the current manager uses.

### 4.4 Async-compatibility invariants

Documented contract, so a future tokio-based consumer (DDM or BGP) is not
blocked by this design:

1. Public manager methods never block on runtime lifecycle work.
2. Factory callbacks execute only on the manager-owned monitor thread —
   an ordinary std thread, safe to `Handle::block_on` from.
3. `Config`/`Runtime` are opaque with minimal `Send + 'static` bounds; an
   async runtime can be a struct of task `JoinHandle`s plus a
   `CancellationToken`, with a factory holding a
   `tokio::runtime::Handle` to spawn from `activate` and `block_on`
   graceful shutdown in `deactivate`.
4. Query closures are synchronous and run under a mutex; they must only
   perform sync-safe, non-blocking reads (no `.await`, no lock-holding
   across suspension points — impossible by construction).

A test factory records the `ThreadId` of every callback to verify
invariant 2.

## 5. NDP / BGP unnumbered instantiation

### 5.1 `ndp` crate

```rust
/// Per-interface NDP config.
#[derive(Clone, Debug, PartialEq)]
pub struct NdpIfConfig {
    /// Router lifetime advertised in transmitted RAs.
    pub router_lifetime: u16,
}

/// Runtime payload: today's RouterDiscoveryRuntime, minus the wrapper.
pub struct NdpRuntime {
    state: Arc<RouterDiscoveryState>,
    threads: RouterDiscoveryThreads,   // Drop joins tx/rx threads
}

pub struct NdpRuntimeFactory {
    log: Logger,
}

impl UnnumberedRuntimeFactory for NdpRuntimeFactory {
    type Config = NdpIfConfig;
    type Runtime = NdpRuntime;
    type Error = ndp::NewRouterDiscoveryError;

    fn activate(&self, ifx, config) -> Result<NdpRuntime, _> {
        // RouterDiscoveryState::new(config.router_lifetime) +
        // RouterDiscoveryThreads::start(...)
    }

    fn reconfigure(&self, runtime, new) -> Reconfigure {
        // Lifetime is interior-mutable on RouterDiscoveryState:
        runtime.state.set_tx_router_lifetime(new.router_lifetime);
        Reconfigure::Updated
    }
    // deactivate: default (Drop joins threads)
}
```

`UnnumberedManagerNdp` wraps `Arc<UnnumberedInterfaceManager<NdpRuntimeFactory>>`
and re-exposes today's `UnnumberedManager` surface: `configure_interface`,
`unconfigure_interface`, `get_neighbor_by_interface`,
`get_interface_for_scope`, `get_manager_state`, `get_pending_interfaces`,
`list_interfaces`, `get_interface_detail`. NDP-specific info structs
(`UnnumberedInterfaceInfo`, `InterfaceDetail`, `DiscoveredRouterState`,
`PendingInterfaceInfo`, `UnnumberedManagerState`) move here. All are
implemented over `with_active`/`for_each_active`, reading neighbor state
from `NdpRuntime.state`.

### 5.2 `bgp` and `mgd` crates

The consumer port moves to `bgp` (with `UnnumberedError` or a
bgp-local equivalent):

```rust
// bgp crate
pub trait BgpUnnumbered: Send + Sync {
    fn get_active_interface_by_scope(&self, scope_id: u32)
        -> Result<Option<BgpUnnumberedInterface>, UnnumberedError>;
    fn get_active_interface(&self, interface: &str)
        -> Result<Option<BgpUnnumberedInterface>, UnnumberedError>;
}

// mgd crate — bridge newtype; mgd depends on both bgp and ndp
pub struct BgpUnnumberedManagerNdp(pub Arc<UnnumberedManagerNdp>);

impl bgp::BgpUnnumbered for BgpUnnumberedManagerNdp { ... }
```

The `From<&DiscoveredRouterState> for
Option<mg_api_types::unnumbered::DiscoveredRouter>` conversion (and any
other `mg_api_types` glue) moves into mgd so neither `unnumbered` nor
`ndp` depends on API types.

## 6. DDM instantiation

### 6.1 Per-interface configuration

The timers currently global in `ddmd/src/main.rs::Arg` become
per-interface; the CLI values act as defaults for newly configured
interfaces:

```rust
#[derive(Clone, Debug, PartialEq)]
pub struct DdmIfConfig {
    /// Milliseconds between solicitations.
    pub solicit_interval: u64,
    /// Milliseconds without an advertisement before expiring a peer.
    pub expire_threshold: u64,
    /// Milliseconds between link-failure checks while waiting for
    /// discovery messages.
    pub discovery_read_timeout: u64,
    /// Milliseconds to wait for exchange responses.
    pub exchange_timeout: u64,
}
```

`reconfigure` keeps the `Restart` default: these values are cloned into
running discovery/exchange components and are not naturally updated in
place.

Not in `DdmIfConfig`:

- `exchange_port` stays daemon-global (factory field).
- `ip_addr_wait` is **repurposed** as ddmd's manager sweep interval,
  preserving today's ~1s address-appearance latency. It no longer has
  per-interface meaning because SMs are created pre-resolved (§6.3). The
  generic sweep enumerates all interfaces in one call rather than
  polling libnet per address object.

### 6.2 Factory and runtime handle

```rust
pub struct DdmRuntimeFactory {
    db: Db,
    hostname: String,
    kind: RouterKind,
    exchange_port: u16,
    dpd: Option<DpdConfig>,
    rt: Arc<tokio::runtime::Handle>,
    /// Every SM gets a clone; events flow back to the hub (§6.4).
    hub_tx: Sender<HubEvent>,
    log: Logger,
}

/// Opaque Runtime payload: a running DDM state machine.
pub struct SmHandle {
    /// Event sender for this SM (discovery, exchange, admin, hub fanout).
    tx: Sender<Event>,
    /// Shared observability state (FSM state, peer identity, stats) for
    /// the admin API and oximeter.
    iface: Arc<InterfaceState>,
    stats: Arc<SessionStats>,
    /// Join handles for the FSM thread and discovery workers; consumed
    /// by deactivate.
    threads: SmThreads,
}

impl UnnumberedRuntimeFactory for DdmRuntimeFactory {
    type Config = DdmIfConfig;
    type Runtime = SmHandle;
    type Error = SmError;

    fn activate(&self, ifx, config) -> Result<SmHandle, SmError> {
        // Build sm::Config PRE-RESOLVED from the manager snapshot:
        //   if_name = ifx.name, if_index = ifx.scope_id.get(),
        //   addr = ifx.ip — no libnet polling, no Init wait loop.
        // Spawn the SM directly into Solicit.
    }

    // reconfigure: default Restart.

    fn deactivate(&self, sm: SmHandle) {
        // Peer-expiry-equivalent removal (§6.5): signal shutdown, join
        // all SM threads, withdraw routes, propagate withdrawals via
        // the hub, clean DPD/tunnel state.
    }
}
```

### 6.3 Pre-resolved activation

`sm::Config` loses `aobj_name` and `ip_addr_wait`; `if_name`, `if_index`,
and `addr` are populated at construction from the manager's interface
snapshot. The Init state's libnet polling loop in `ddm/src/sm/state.rs`
is deleted; the manager is now the component that waits for addresses to
appear, and it restarts the SM if the address or ifindex changes.

### 6.4 Event hub (replaces per-SM fan-out vectors)

Today each `SmContext` carries a frozen `event_channels:
Vec<Sender<Event>>` built positionally at startup; fan-out sites
(`ddm/src/exchange/runtime.rs` transit redistribution,
`ddm/src/sm/state.rs` expiry withdrawal) iterate it with `.unwrap()`
sends. This cannot survive dynamic membership: cloned contexts hold stale
vectors and a removed receiver would panic surviving SMs.

Replacement: one MPSC hub owned by the DDM adapter. The generic manager
knows nothing about it.

```rust
pub enum HubEvent {
    /// Redistribute an update to all active SMs except the origin.
    Redistribute {
        from: String,                      // origin interface name
        update: ddm_protocol::v3::Update,
    },
    /// Deliver an admin event to all active SMs. Admin events flow
    /// through the same queue as redistribution — no jumping the queue,
    /// one enqueue order for everything.
    Admin(AdminEvent),
    /// Terminate the hub thread (explicit shutdown, §6.6).
    Shutdown,
}
```

`SmContext` changes: drop `event_channels`, add `hub_tx:
Sender<HubEvent>`. All cross-SM sends become sends into the hub.

Hub thread loop:

1. `recv()` a `HubEvent` (exit on `Shutdown` or disconnect).
2. Under the manager's active-map lock (via `for_each_active`), collect
   `(name, Sender<Event>)` pairs — clone senders, release the lock.
3. Send to recipients outside the lock: `Redistribute` skips
   `name == from`; `Admin` goes to all. Sends are **fallible** — a
   receiver that disappeared mid-flight is logged-and-skipped, never
   unwrapped. Stale queued events for a removed interface are harmless.

The active `ActiveMap` is the authoritative registry of running SMs. The
admin API (`HandlerContext`) and oximeter derive their views from it
instead of holding fixed `Vec<SmContext>` / `Vec<Sender<Event>>`
snapshots.

### 6.5 Removal semantics

Removing an interface behaves like peer expiry on that interface:

1. Signal SM shutdown; join the FSM thread, the four discovery worker
   threads (solicitation sender, multicast listener, unicast listener,
   expiry checker), the exchange server, and any initial-pull retry
   thread. Postcondition: no threads or sockets remain for the interface,
   preserving the existing socket release sequencing.
2. Withdraw the peer's routes from the kernel/DPD as expiry does today.
3. Propagate transit withdrawals to surviving SMs via the hub.
4. Clean tunnel state as appropriate.

### 6.6 `DdmInterfaceManager` composition and shutdown ordering

```rust
pub struct DdmInterfaceManager {
    inner: Arc<UnnumberedInterfaceManager<DdmRuntimeFactory>>,
    hub_tx: Sender<HubEvent>,
    hub_thread: ManagedThread,
}
```

Construction order (no cycles: hub holds a manager handle; the manager
never holds the hub):

1. Create hub channel.
2. Build `DdmRuntimeFactory` with a `hub_tx` clone.
3. `UnnumberedInterfaceManager::new(factory, sweep, log)`.
4. Spawn hub thread with `Arc` clone of the manager + `hub_rx`.

Shutdown must be explicit rather than purely drop-driven, because admin
handler contexts may hold `hub_tx` clones that outlive the manager:

1. Drop/shut down `inner`: monitor drains, `deactivate`s every SM
   (joining threads; their `hub_tx` clones drop), then exits and drops
   the factory (dropping its `hub_tx`).
2. Send `HubEvent::Shutdown` on the manager's own `hub_tx` (ordered
   after all SM-originated events), then drop it.
3. Join the hub thread. (Disconnect remains a fallback exit path.)

### 6.7 CLI / SMF cutover (one-shot, no `-a` compatibility)

- `ddmd` accepts `-i/--interface <name>` (interface names); the `-a`
  address-object form is removed in the same change.
- `smf/ddm_method_script.sh` translates existing `config/interfaces`
  values (address objects like `tfportrear0_0/ll`) to interface names
  with `${x%%/*}` and passes `--interface`; bare interface names pass
  through unchanged. This lets the whole cutover ship in one commit while
  omicron still delivers address objects.
- Sweep all other direct `-a` launchers in the same change:
  `.github/buildomat`, `tests/` (mg-tests harness), falcon/clab/lab
  scripts, plus any remaining `rg -- '-a '` hits.
- Omicron later switches `config/interfaces` values to plain interface
  names (PR 5).

## 7. Implementation plan

Five stacked PRs, each independently testable, atop
`trey/unnumbered-cleanup` (#800).

### PR 1 — Genericize `unnumbered` in place

No dependent-crate changes; `unnumbered` still depends on `ndp` and NDP
behavior stays instantiated inside the crate temporarily.

Changes in `unnumbered/src/`:

- New `factory.rs`: `UnnumberedRuntimeFactory`, `Reconfigure`.
- `interface.rs` → generic `ActiveEntry<F>` + `ActiveMap<F>` (rename of
  `InterfaceMap`, same accessor surface). The current
  `RouterDiscoveryRuntime` enum content becomes the NDP factory's
  `Runtime` type (temporarily still in this crate).
- `manager.rs` → `UnnumberedInterfaceManager<F>` + private
  `LifecycleDriver<F>` + `Shared<F>` per §4.3. Reconciler logic ports
  from `reconcile_interfaces_with_activator` with `F::Config` replacing
  the hard-coded `u16` router lifetime and the reconfigure arm replacing
  the `set_tx_router_lifetime` special case.
- `unconfigure` becomes desired-state-removal + wake (teardown moves to
  the monitor thread). Monitor disconnect path drains active entries via
  `factory.deactivate`.
- `new()` gains the `sweep_interval` parameter; mgd passes the current
  5s constant.
- Multi-link-local selection becomes deterministic (lowest address).
- Keep the existing `UnnumberedManager` public API as a thin wrapper /
  alias over `UnnumberedInterfaceManager<NdpRuntimeFactory>` so `mgd`
  and `bgp` compile unchanged.

Tests:

- Port all existing reconciler tests (flap/reactivate, scope change,
  addr change, retained unchanged, failed activation retry, unconfigure,
  pending derivation, lifetime in-place update) onto a `TestFactory`
  whose `Runtime` records activations/deactivations.
- New: callback-thread test — `TestFactory` records `ThreadId` per
  callback; assert all equal the monitor thread's id.
- New: reconfigure `Restart` path (deactivate + reactivate observed).
- Keep the `ActiveMap` proptest.
- Full workspace build + tests; zero behavior change for mgd/bgp.

### PR 2 — Crate moves

- Move `Ipv6NetworkInterface` into `unnumbered`; flip the dep so `ndp`
  depends on `unnumbered` (re-export from `ndp` for source compat if
  convenient).
- Move `NdpRuntimeFactory`, `NdpRuntime`, `NdpIfConfig`,
  `UnnumberedManagerNdp`, and the NDP info structs into `ndp` (§5.1).
- Move `BgpUnnumbered`, `BgpUnnumberedInterface`, `UnnumberedError` into
  `bgp`; remove `bgp → unnumbered`.
- Add `mgd::BgpUnnumberedManagerNdp` bridge newtype; move
  `mg_api_types` conversions into mgd; `unnumbered` drops its
  `mg-api-types` dep.
- `unnumbered` is now generic-only. OpenAPI output and runtime behavior
  unchanged (verify with `cargo xtask` openapi checks / existing tests).

### PR 3 — DDM lifecycle hardening (no manager integration yet)

Prerequisite work so an SM can actually be stopped:

- `StateMachine::run()` returns/retains join handles (`SmThreads`);
  every FSM state observes a shutdown signal.
- Discovery handler retains and joins its four worker threads; workers
  exit on shutdown signal or closed channel instead of spinning.
- Exchange server and the transient initial-pull retry thread stop on
  shutdown.
- All cross-SM sends become fallible (no `.unwrap()`); closed channels
  cause clean exits.
- Teardown postcondition: no SM/discovery threads or sockets remain;
  existing socket release ordering preserved.
- Tests: start/stop an SM repeatedly on a lab interface (or loopback
  harness) asserting thread/socket teardown.

### PR 4 — Dynamic DDM manager

- `DdmIfConfig`, `DdmRuntimeFactory`, `SmHandle`,
  `DdmInterfaceManager`, `HubEvent` + hub thread per §6.
- Pre-resolved activation; delete the Init libnet polling loop.
- `SmContext`: drop `event_channels`, add `hub_tx`; rewrite fan-out
  sites (`exchange/runtime.rs`, `sm/state.rs`) to hub sends.
- Admin API and oximeter derive from the active map; `HandlerContext`
  holds `Arc<DdmInterfaceManager>`.
- New admin endpoints: add/remove interface (name + optional
  `DdmIfConfig` overrides), list configured/pending/active interfaces.
- Removal as peer expiry (§6.5); explicit shutdown ordering (§6.6).
- `ip_addr_wait` becomes the manager sweep interval; CLI/SMF cutover to
  interface names (§6.7) including the method script and all launcher
  sweeps.
- Tests: mg-tests coverage for dynamic add/remove, address flap,
  ifindex change, redistribution correctness after membership change.

### PR 5 — Omicron counterpart

- `config/interfaces` values become interface names.
- Adjust service/config plumbing and any RSS/sled-agent references to
  ddm address objects.

## 8. Open review questions

1. **Dual-protocol exclusion placement** — nexus vs. maghemite-local
   enforcement (deferred; see §2).
2. **Deterministic multi-link-local selection** — semantic change from
   explicit address-object selection; lowest-address rule proposed.
3. **Eventually-consistent unconfigure** — teardown moves off the caller
   thread onto the monitor; API callers observe removal asynchronously
   via pending/active queries.
