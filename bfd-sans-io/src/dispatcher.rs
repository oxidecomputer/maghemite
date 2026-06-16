// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::AddPeerError;
use bfd::packet;
use slog::Logger;
use slog::warn;
use slog_error_chain::InlineErrorChain;
use std::collections::HashMap;
use std::collections::hash_map;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// The per-listener table mapping a peer IP to the channel on which packets
/// from that peer should be delivered. Shared between a [`Listener`] and the
/// task reading from its socket.
type SharedSessions =
    Arc<RwLock<HashMap<IpAddr, mpsc::Sender<packet::Control>>>>;

pub(crate) enum ListenerRemovePeerResult {
    RemovedButOtherPeersRemain,
    RemovedNowEmpty,
    NotRemoved,
}

/// `Dispatcher` manages tokio tasks that listen for incoming packets and
/// dispatches them to a channel tied to a specific peer IP address.
///
/// This allows us to have multiple peer IPs associated with a single local
/// listening address (e.g., `*:3784`).
pub(crate) struct Dispatcher {
    // Invariants maintained between these maps: For any given peer that exists
    // in `peer_to_listen_addr`, there must be a corresponding listener recorded
    // in `listeners`. When the last peer for a given listening address is
    // removed, that listener is also removed.

    // peer IP -> associated local listening address
    peer_to_listen_addr: HashMap<IpAddr, SocketAddr>,

    // local address -> listener task
    listeners: HashMap<SocketAddr, Listener>,

    // How we bind listening sockets and spawn their receive tasks. Production
    // uses `TokioUdpBinder`; tests inject a fake so the dispatcher's bookkeeping
    // can be exercised without binding real sockets.
    backend: Arc<dyn ListenerBackend>,
}

impl Dispatcher {
    pub(crate) fn new() -> Self {
        Self::with_backend(Arc::new(TokioUdpBinder))
    }

    fn with_backend(backend: Arc<dyn ListenerBackend>) -> Self {
        Self {
            peer_to_listen_addr: HashMap::default(),
            listeners: HashMap::default(),
            backend,
        }
    }

    pub(crate) fn listen_addr_for_peer(
        &self,
        peer: &IpAddr,
    ) -> Option<SocketAddr> {
        self.peer_to_listen_addr.get(peer).copied()
    }

    /// Ensure we're listening on a socket at `listen_addr` for incoming packets
    /// from `peer`.
    ///
    /// On success, returns a channel on which packets from that peer will be
    /// sent. The sender expects the receiver to promptly drain the channel; the
    /// channel size is relatively small, and if the channel fills up, the
    /// sender will drop incoming packets until the channel has room.
    pub(crate) fn ensure(
        &mut self,
        listen_addr: SocketAddr,
        peer: IpAddr,
        log: &Logger,
    ) -> Result<mpsc::Receiver<packet::Control>, AddPeerError> {
        if self.peer_to_listen_addr.contains_key(&peer) {
            return Err(AddPeerError::PeerExists(peer));
        }

        // This is the channel between the listening task and the
        // `SessionEgressTask` responsible for managing the state machine.
        // `SessionEgressTask::run()` should promptly pull messages off of this
        // channel; the only times it `.await`s something without simultaneously
        // receiving on this channel is binding the egress socket, which should
        // be very fast. We should be fine with a pretty small channel buffer;
        // if we start receiving packets faster than the egress task can process
        // them, we'll drop packets.
        let (tx, rx) = mpsc::channel(8);

        match self.listeners.entry(listen_addr) {
            hash_map::Entry::Occupied(entry) => {
                entry.get().insert_peer(peer, tx)?;
            }
            hash_map::Entry::Vacant(entry) => {
                let listener = Listener::new(
                    &*self.backend,
                    listen_addr,
                    peer,
                    tx,
                    log.clone(),
                )?;
                entry.insert(listener);
            }
        }

        self.peer_to_listen_addr.insert(peer, listen_addr);
        Ok(rx)
    }

    /// Remove the tie between a listening task and a peer.
    ///
    /// If we don't have a listener associated with `peer`, does nothing and
    /// returns `None`.
    ///
    /// If we have a listener associated with `peer` but there are still other
    /// peers associated with the same listener, removes the association with
    /// this peer and returns `None`.
    ///
    /// If this removes the final peer associated with a local listening
    /// address, returns `Some(handle)` with a handle that can be used to await
    /// the listener socket being closed.
    pub(crate) fn remove(
        &mut self,
        peer: IpAddr,
    ) -> Option<ListenerShutdownHandle> {
        // Do we have a listener for this peer address? If not, we're done.
        let local_addr = self.peer_to_listen_addr.remove(&peer)?;

        // We do: there must be a listener here.
        let Some(listener) = self.listeners.get(&local_addr) else {
            debug_assert!(
                false,
                "Dispatcher hash maps out of sync: \
                 peer {peer} should have a listener at {local_addr}"
            );
            return None;
        };

        match listener.remove_peer(peer) {
            ListenerRemovePeerResult::RemovedNowEmpty => {
                // we can safely `unwrap()` this: we _have_ a reference to the
                // `listener` now, which we got from the map by this same key.
                // we know it's still there.
                let listener = self.listeners.remove(&local_addr).unwrap();
                Some(ListenerShutdownHandle(listener))
            }
            ListenerRemovePeerResult::RemovedButOtherPeersRemain
            | ListenerRemovePeerResult::NotRemoved => None,
        }
    }
}

/// Handle to a recently-removed `Listener` task.
///
/// Callers can use this handle to wait for the listener's associated tokio task
/// to be shut down, ensuring the listening socket has been closed (and the port
/// is free for reuse by a newer listener).
#[must_use]
pub struct ListenerShutdownHandle(Listener);

impl ListenerShutdownHandle {
    pub async fn shutdown(self) {
        self.0.shutdown().await;
    }
}

/// Handle to a single listening task.
struct Listener {
    /// Map shared with the inner listening task that contains the peers we're
    /// listening for and the channel on which we should send any incoming
    /// packets from that peer.
    sessions: SharedSessions,
    listen_task: Option<JoinHandle<()>>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(listen_task) = self.listen_task.take() {
            listen_task.abort();
        }
    }
}

impl Listener {
    fn new(
        backend: &dyn ListenerBackend,
        listen_addr: SocketAddr,
        peer: IpAddr,
        tx: mpsc::Sender<packet::Control>,
        log: Logger,
    ) -> Result<Self, AddPeerError> {
        let sessions: SharedSessions =
            Arc::new(RwLock::new(HashMap::from_iter([(peer, tx)])));

        let listen_task =
            backend.spawn(listen_addr, Arc::clone(&sessions), log)?;

        Ok(Self {
            sessions,
            listen_task,
        })
    }

    async fn shutdown(mut self) {
        if let Some(listen_task) = self.listen_task.take() {
            listen_task.abort();
            // Discard the result; this can only fail if the listen task
            // panicked, but we're shutting it down anyway.
            let _: Result<_, _> = listen_task.await;
        }
    }

    fn remove_peer(&self, peer: IpAddr) -> ListenerRemovePeerResult {
        let mut sessions = self.sessions.write().unwrap();
        if sessions.remove(&peer).is_some() {
            if sessions.is_empty() {
                ListenerRemovePeerResult::RemovedNowEmpty
            } else {
                ListenerRemovePeerResult::RemovedButOtherPeersRemain
            }
        } else {
            ListenerRemovePeerResult::NotRemoved
        }
    }

    fn insert_peer(
        &self,
        peer: IpAddr,
        tx: mpsc::Sender<packet::Control>,
    ) -> Result<(), AddPeerError> {
        let mut sessions = self.sessions.write().unwrap();
        match sessions.entry(peer) {
            hash_map::Entry::Occupied(_) => Err(AddPeerError::PeerExists(peer)),
            hash_map::Entry::Vacant(entry) => {
                entry.insert(tx);
                Ok(())
            }
        }
    }
}

/// Abstraction over binding a listening socket and spawning the task that reads
/// from it.
///
/// Production uses [`TokioUdpBinder`]; tests inject a fake so `Dispatcher`'s
/// bookkeeping can be exercised without touching the network.
trait ListenerBackend: Send + Sync + 'static {
    /// Bind a socket at `listen_addr` and spawn a task that reads packets and
    /// dispatches them to the per-peer channels in `sessions`.
    ///
    /// Returns the spawned task's handle, or `None` for test fakes that don't
    /// bind a real socket. A `Listener` holding `None` is shut down/dropped as
    /// a no-op.
    fn spawn(
        &self,
        listen_addr: SocketAddr,
        sessions: SharedSessions,
        log: Logger,
    ) -> Result<Option<JoinHandle<()>>, AddPeerError>;
}

/// Production [`ListenerBackend`]: binds a real UDP socket and spawns a
/// [`ListenerTask`] to read from it.
struct TokioUdpBinder;

impl ListenerBackend for TokioUdpBinder {
    fn spawn(
        &self,
        listen_addr: SocketAddr,
        sessions: SharedSessions,
        log: Logger,
    ) -> Result<Option<JoinHandle<()>>, AddPeerError> {
        // This is pretty spicy: we're using std's `UdpSocket` so we can
        // _synchronously_ bind, even though this function is ultimately called
        // from an async context. The arguments for this are:
        //
        // 1. Binding a UDP socket doesn't involve any network traffic, so
        //    shouldn't block for long
        // 2. Reworking this to allow async binding is pretty involved; we'd
        //    need to either use an async Mutex (lots of footguns there) or move
        //    to an actor task pattern to manage the listeners.
        let socket = std::net::UdpSocket::bind(listen_addr).map_err(|err| {
            AddPeerError::Bind {
                addr: listen_addr,
                err,
            }
        })?;
        socket
            .set_nonblocking(true)
            .map_err(AddPeerError::SetSocketNonBlocking)?;
        let socket =
            UdpSocket::from_std(socket).map_err(AddPeerError::StdToTokio)?;

        let listen_task = ListenerTask::new(socket, sessions, log);
        Ok(Some(tokio::spawn(listen_task.run())))
    }
}

struct ListenerTask {
    socket: UdpSocket,
    sessions: SharedSessions,
    log: Logger,
}

impl ListenerTask {
    fn new(socket: UdpSocket, sessions: SharedSessions, log: Logger) -> Self {
        Self {
            socket,
            sessions,
            log,
        }
    }

    async fn run(self) {
        // Maximum length of a BFD packet is on the order of 100 bytes (RFC
        // 5880).
        let mut buf = [0; 1024];

        loop {
            let (buf, peer) = match self.socket.recv_from(&mut buf).await {
                Ok((n, peer)) => (&buf[..n], peer),
                Err(err) => {
                    warn!(
                        self.log, "udp recv error";
                        "local" => ?self.socket.local_addr(),
                        InlineErrorChain::new(&err),
                    );
                    continue;
                }
            };

            // Do we expect traffic from this peer address?
            let Some(tx) =
                self.sessions.read().unwrap().get(&peer.ip()).cloned()
            else {
                warn!(
                    self.log, "unknown peer; dropping";
                    "local" => ?self.socket.local_addr(),
                    "peer" => %peer,
                );
                continue;
            };

            // Parse the packet.
            let pkt = match packet::Control::from_bytes(buf) {
                Ok(pkt) => pkt,
                Err(err) => {
                    warn!(
                        self.log, "error parsing control packet";
                        "local" => ?self.socket.local_addr(),
                        "peer" => %peer,
                        InlineErrorChain::new(&*err),
                    );
                    continue;
                }
            };

            // Try to send the packet on our tx channel.
            //
            // We intentionally don't use `tx.send(pkt).await` here: that blocks
            // indefinitely waiting for room in the channel; we would rather
            // discard packets if we can't keep up so we can continue to receive
            // new incoming packets. Once the channel frees up space we'll be
            // able to send again.
            match tx.try_send(pkt) {
                Ok(()) => (),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        self.log, "udp ingress channel full; dropping packet";
                        "local" => ?self.socket.local_addr(),
                        "peer" => %peer,
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!(
                        self.log, "udp ingress channel closed";
                        "local" => ?self.socket.local_addr(),
                        "peer" => %peer,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
