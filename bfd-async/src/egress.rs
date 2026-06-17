// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! [`EgressTask`] is one of the tasks comprising a BFD session; it owns the UDP
//! socket used to send control packets to the peer.
//!
//! The session driver hands serialized control packets to this task over a
//! channel.
//!
//! This task manages the complexity of the socket lifetime, which may be
//! nontrivial in some cases: single-hop BFD sessions are required by the RFC to
//! use a src port in a particular 16,384-long range, so we have to attempt to
//! bind a socket with a specific port instead of binding to port 0. We have no
//! control over which ports in that range are actually free, so we limit
//! ourselves to trying at most `MAX_SRC_PORTS_TRIED_PER_BIND_ATTEMPT` binds
//! (each with a different source port) any time we try to bind a socket. We
//! attempt a bind:
//!
//! 1. On startup.
//! 2. Any time we get a packet to send from the driver and we don't already
//!    have a bound socket.
//!
//! We can get into case 2 two ways:
//!
//! * Our initial startup bind fails; then when we get the first packet from the
//!   driver, we don't have a bound socket so will try to bind again.
//! * If we fail a `send_to()`, we close our current socket and will rebind on
//!   the next packet from the driver.

use crate::single_hop_egress_src_port::SingleHopEgressSrcPort;
use bfd::DEFAULT_BFD_TTL;
use bfd::SessionCounters;
use slog::Logger;
use slog::warn;
use slog_error_chain::InlineErrorChain;
use socket2::Socket;
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How many successive source ports we'll try in a single bind attempt before
/// giving up (and dropping the current outgoing packet).
const MAX_SRC_PORTS_TRIED_PER_BIND_ATTEMPT: NonZeroUsize =
    NonZeroUsize::new(16).unwrap();

#[derive(Debug, thiserror::Error)]
enum BindEgressSocketError {
    #[error("failed to bind egress socket")]
    Bind(#[source] io::Error),

    #[error(
        "failed to find free src port for single-hop egress socket: \
         tried {first_port_tried}..={last_port_tried}"
    )]
    SingleHopNoSrcPort {
        first_port_tried: u16,
        last_port_tried: u16,
    },

    #[error("failed to convert tokio socket to std socket")]
    TokioToStd(#[source] io::Error),

    #[error("failed to set socket TTL")]
    SetTtl(#[source] io::Error),

    #[error("failed to convert std socket to tokio socket")]
    StdToTokio(#[source] io::Error),
}

// Multihop sessions can use a source port of 0, but singlehop sessions must use
// a port in a specified range (supplied by `SingleHopEgressSrcPort`).
pub(crate) enum EgressMode {
    SingleHop(Arc<SingleHopEgressSrcPort>),
    MultiHop,
}

pub(crate) struct EgressTask {
    egress_rx: mpsc::Receiver<Vec<u8>>,
    socket: Option<UdpSocket>,
    local_ip: IpAddr,
    remote_addr: SocketAddr,
    mode: EgressMode,
    counters: Arc<SessionCounters>,
    log: Logger,
}

impl EgressTask {
    pub(crate) fn new(
        egress_rx: mpsc::Receiver<Vec<u8>>,
        local_ip: IpAddr,
        remote_addr: SocketAddr,
        mode: EgressMode,
        counters: Arc<SessionCounters>,
        log: Logger,
    ) -> Self {
        Self {
            egress_rx,
            socket: None,
            local_ip,
            remote_addr,
            mode,
            counters,
            log,
        }
    }

    pub(crate) async fn run(mut self) {
        // Preemptively attempt to bind an egress socket and store in in
        // `self.socket`; if this fails, we'll try again when we get our first
        // packet to send.
        if let Some(socket) = self.try_bind_socket().await {
            self.socket = Some(socket);
        }

        // Run until the sending half of this channel (held by the session
        // driver) is closed, which means the session is being torn down.
        while let Some(bytes) = self.egress_rx.recv().await {
            self.send(&bytes).await;
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        let socket = match &self.socket {
            Some(socket) => socket,
            None => {
                // Bind a new socket if we don't have one available already
                // (i.e., we failed all previous bind attempts, or we failed a
                // previous `send_to()` and closed the socket).
                match self.try_bind_socket().await {
                    Some(socket) => self.socket.insert(socket),
                    None => {
                        // No usable socket; drop this packet and try again on
                        // the next one.
                        self.counters
                            .control_packet_send_failures
                            .fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        };

        match socket.send_to(bytes, self.remote_addr).await {
            Ok(_n) => {
                self.counters
                    .control_packets_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                self.counters
                    .control_packet_send_failures
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    self.log, "udp egress send_to failed; will rebind";
                    "remote" => %self.remote_addr,
                    InlineErrorChain::new(&err),
                );
                // Drop the socket so the next packet triggers a fresh bind.
                //
                // TODO-correctness Should we _always_ drop and rebind on a send
                // failure, or should we be matching on particular kinds of
                // errors? Always rebinding is consistent with the prior (sync)
                // implementation.
                self.socket = None;
            }
        }
    }

    async fn try_bind_socket(&self) -> Option<UdpSocket> {
        let result = match &self.mode {
            EgressMode::SingleHop(egress_src_port) => {
                try_bind_singlehop_with_max_src_port_tries(
                    self.local_ip,
                    egress_src_port,
                    MAX_SRC_PORTS_TRIED_PER_BIND_ATTEMPT,
                )
                .await
            }
            EgressMode::MultiHop => {
                bind_egress_socket(SocketAddr::new(self.local_ip, 0)).await
            }
        };

        match result {
            Ok(socket) => Some(socket),
            Err(err) => {
                warn!(
                    self.log,
                    "failed to bind egress socket";
                    InlineErrorChain::new(&err),
                );
                None
            }
        }
    }
}

async fn try_bind_singlehop_with_max_src_port_tries(
    local_ip: IpAddr,
    src_port: &SingleHopEgressSrcPort,
    max_ports_to_try: NonZeroUsize,
) -> Result<UdpSocket, BindEgressSocketError> {
    let mut first_port_tried = None;
    let mut last_port_tried = None;
    for _ in 0..max_ports_to_try.get() {
        let src_port = src_port.next();

        // Keep track of what ports we tried exclusively for the error we return
        // if we fail to find a free port.
        if first_port_tried.is_none() {
            first_port_tried = Some(src_port);
        }
        last_port_tried = Some(src_port);

        let local_addr = SocketAddr::new(local_ip, src_port);
        match bind_egress_socket(local_addr).await {
            Ok(socket) => return Ok(socket),
            Err(BindEgressSocketError::Bind(err))
                if err.kind() == io::ErrorKind::AddrInUse =>
            {
                continue;
            }
            Err(err) => return Err(err),
        }
    }

    Err(BindEgressSocketError::SingleHopNoSrcPort {
        // We know these must be `Some(_)` becaues `max_ports_to_try` is a
        // `NonZeroUsize`, so we must have iterated at least once in the for
        // loop above, and the first iteration sets both these values.
        first_port_tried: first_port_tried.unwrap(),
        last_port_tried: last_port_tried.unwrap(),
    })
}

async fn bind_egress_socket(
    local_addr: SocketAddr,
) -> Result<UdpSocket, BindEgressSocketError> {
    let sock = UdpSocket::bind(local_addr)
        .await
        .map_err(BindEgressSocketError::Bind)?;
    let sock = sock.into_std().map_err(BindEgressSocketError::TokioToStd)?;
    let sock = Socket::from(sock);

    let ttl_result = match local_addr {
        SocketAddr::V4(_) => sock.set_ttl_v4(DEFAULT_BFD_TTL),
        SocketAddr::V6(_) => sock.set_unicast_hops_v6(DEFAULT_BFD_TTL),
    };
    ttl_result.map_err(BindEgressSocketError::SetTtl)?;

    UdpSocket::from_std(sock.into()).map_err(BindEgressSocketError::StdToTokio)
}

#[cfg(test)]
mod tests;
