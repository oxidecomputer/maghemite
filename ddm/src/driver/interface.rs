// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The per-interface task: feed inputs to an
//! [`InterfaceSm`](crate::protocol::interface::InterfaceSm), perform the
//! actions it returns.
//!
//! Exchange requests are awaited inline. That is deliberate: ddm is a delta
//! protocol, so a peer that sees an announce and a withdraw out of order ends
//! up with the wrong table, and the core only ever asks for one exchange
//! operation at a time. Waiting here stalls this interface and nothing else.

use crate::discovery::Version;
use crate::discovery::runtime::{self as discovery, Sockets};
use crate::driver::rib::HubEvent;
use crate::exchange::runtime::{self as exchange, Endpoint, ServerContext};
use crate::protocol::interface::{Action, IfAddr, Input, InterfaceSm, Outcome};
use crate::sm::SmContext;
use crate::{err, inf, wrn};
use ddm_protocol_types::v3;
use libnet::get_ipaddr_info;
use mg_common::lock;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::timeout_at;

/// How long to wait between attempts to bind the exchange server.
const EXCHANGE_BIND_RETRY: Duration = Duration::from_secs(1);

/// How long to wait between probes of our own exchange server while waiting
/// for it to start answering.
const EXCHANGE_READY_POLL: Duration = Duration::from_millis(250);

pub fn spawn(
    ctx: SmContext,
    index: usize,
    hub: UnboundedSender<HubEvent>,
    ingress: UnboundedSender<Input>,
    rx: UnboundedReceiver<Input>,
) -> JoinHandle<()> {
    let config = crate::protocol::interface::Config {
        aobj_name: ctx.config.aobj_name.clone(),
        hostname: ctx.hostname.clone(),
        kind: ctx.config.kind,
        solicit_interval: Duration::from_millis(ctx.config.solicit_interval),
        expire_threshold: Duration::from_millis(ctx.config.expire_threshold),
        ip_addr_wait: Duration::from_millis(ctx.config.ip_addr_wait),
        exchange_bind_retry: EXCHANGE_BIND_RETRY,
        exchange_ready_poll: EXCHANGE_READY_POLL,
    };

    let driver = Driver {
        sm: InterfaceSm::new(config, Instant::now()),
        ctx,
        index,
        hub,
        ingress,
        discovery: None,
        server: None,
    };

    tokio::spawn(driver.run(rx))
}

struct Driver {
    sm: InterfaceSm,

    /// Addressing in `ctx.config` is filled in once the address object
    /// resolves. [`crate::sys::program`] and the exchange URIs both need it.
    ctx: SmContext,

    index: usize,
    hub: UnboundedSender<HubEvent>,
    ingress: UnboundedSender<Input>,
    discovery: Option<Discovery>,
    server: Option<exchange::Server>,
}

impl Driver {
    async fn run(mut self, mut rx: UnboundedReceiver<Input>) {
        // Actions that produce an outcome feed it straight back, ahead of
        // anything waiting on the channel.
        let mut queue: VecDeque<Input> = VecDeque::new();

        loop {
            let input = match queue.pop_front() {
                Some(input) => input,
                None => match self.next(&mut rx).await {
                    Some(input) => input,
                    // Nothing closes the ingress channel; this is here because
                    // `recv` has to return something once every sender is gone.
                    None => return,
                },
            };

            for action in self.sm.handle(input, Instant::now()) {
                if let Some(input) = self.execute(action).await {
                    queue.push_back(input);
                }
            }

            self.publish();
        }
    }

    async fn next(&self, rx: &mut UnboundedReceiver<Input>) -> Option<Input> {
        match self.sm.next_deadline() {
            Some(deadline) => {
                match timeout_at(deadline.into(), rx.recv()).await {
                    Ok(input) => input,
                    Err(_) => Some(Input::Timer),
                }
            }
            None => rx.recv().await,
        }
    }

    async fn execute(&mut self, action: Action) -> Option<Input> {
        let if_name = self.ctx.config.if_name.clone();
        match action {
            Action::ResolveAddr => Some(Input::Addr(self.resolve().await)),

            Action::OpenSockets(addr) => self.open_sockets(addr).await,

            Action::CloseSockets => {
                self.discovery = None;
                None
            }

            Action::StartExchangeServer => Some(Input::Outcome(
                Outcome::ExchangeServerStarted(self.start_server()),
            )),

            Action::StopExchangeServer => {
                self.server = None;
                None
            }

            Action::SelfPull => {
                let self_addr = self.endpoint(self.ctx.config.addr);
                let ok = match exchange::pull(self_addr, Version::V3).await {
                    Ok(_) => true,
                    Err(e) => {
                        wrn!(
                            self.ctx.log,
                            if_name,
                            "exchange server not started: {e}"
                        );
                        false
                    }
                };
                Some(Input::Outcome(Outcome::SelfPull(ok)))
            }

            Action::PeerPull { peer, version } => {
                let result =
                    match exchange::pull(self.endpoint(peer), version).await {
                        Ok(response) => {
                            Some(Box::new(v3::Update::announce(response)))
                        }
                        Err(e) => {
                            wrn!(self.ctx.log, if_name, "exchange pull: {e}");
                            None
                        }
                    };
                Some(Input::Outcome(Outcome::PeerPull(result)))
            }

            Action::Solicit => {
                let Some(sockets) = self.sockets() else {
                    return Some(Input::SolicitFailed);
                };
                match sockets.solicit().await {
                    Ok(_) => None,
                    Err(e) => {
                        err!(self.ctx.log, if_name, "solicit failed: {e}");
                        Some(Input::SolicitFailed)
                    }
                }
            }

            Action::Advertise { to } => {
                if let Some(sockets) = self.sockets()
                    && let Err(e) = sockets.advertise(Some(to)).await
                {
                    err!(self.ctx.log, if_name, "advertise: {e}");
                }
                None
            }

            Action::SendUpdate {
                peer,
                version,
                update,
            } => {
                let ok = match exchange::push(
                    self.endpoint(peer),
                    version,
                    &update,
                    Duration::from_millis(self.ctx.config.exchange_timeout),
                )
                .await
                {
                    Ok(()) => true,
                    Err(e) => {
                        err!(
                            self.ctx.log,
                            if_name,
                            "push to {peer}: {e}, expiring peer"
                        );
                        false
                    }
                };
                Some(Input::Outcome(Outcome::UpdateSent(ok)))
            }

            Action::Rib(event) => {
                if let Err(e) = self.hub.send(HubEvent {
                    event,
                    origin: self.index,
                    config: self.ctx.config.clone(),
                    stats: self.ctx.stats.clone(),
                }) {
                    err!(self.ctx.log, if_name, "route hub gone: {e}");
                }
                None
            }
        }
    }

    async fn resolve(&self) -> Option<IfAddr> {
        let aobj_name = self.ctx.config.aobj_name.clone();
        let info = match tokio::task::spawn_blocking(move || {
            get_ipaddr_info(&aobj_name)
        })
        .await
        {
            Ok(Ok(info)) => info,
            Ok(Err(e)) => {
                wrn!(
                    self.ctx.log,
                    self.ctx.config.if_name,
                    "failed to get IPv6 address for interface {}: {e}",
                    self.ctx.config.aobj_name
                );
                return None;
            }
            Err(e) => {
                err!(
                    self.ctx.log,
                    self.ctx.config.if_name,
                    "address lookup task: {e}"
                );
                return None;
            }
        };

        match info.addr {
            IpAddr::V6(addr) => Some(IfAddr {
                ifname: info.ifname,
                index: info.index as u32,
                addr,
            }),
            IpAddr::V4(_) => {
                wrn!(
                    self.ctx.log,
                    self.ctx.config.if_name,
                    "specified address {} is not IPv6",
                    self.ctx.config.aobj_name
                );
                None
            }
        }
    }

    async fn open_sockets(&mut self, addr: IfAddr) -> Option<Input> {
        self.ctx.config.if_name.clone_from(&addr.ifname);
        self.ctx.config.if_index = addr.index;
        self.ctx.config.addr = addr.addr;

        inf!(
            self.ctx.log,
            self.ctx.config.if_name,
            "sm initialized with addr {} on if {} index {}",
            addr.addr,
            addr.ifname,
            addr.index,
        );

        let sockets = match Sockets::open(
            self.ctx.hostname.clone(),
            self.ctx.config.kind,
            addr.addr,
            addr.index,
        ) {
            Ok(sockets) => Arc::new(sockets),
            Err(e) => {
                err!(
                    self.ctx.log,
                    self.ctx.config.if_name,
                    "discovery sockets on {}: {e}",
                    addr.addr
                );
                // Pace the retry. Falling straight back to address resolution
                // would spin on a link whose sockets never open.
                tokio::time::sleep(Duration::from_millis(
                    self.ctx.config.ip_addr_wait,
                ))
                .await;
                return Some(Input::SolicitFailed);
            }
        };

        self.discovery = Some(Discovery {
            readers: vec![
                self.reader(sockets.clone(), false),
                self.reader(sockets.clone(), true),
            ],
            sockets,
        });
        None
    }

    fn reader(&self, sockets: Arc<Sockets>, unicast: bool) -> JoinHandle<()> {
        let ingress = self.ingress.clone();
        let log = self.ctx.log.clone();
        let if_name = self.ctx.config.if_name.clone();
        tokio::spawn(async move {
            loop {
                let sock = if unicast { &sockets.uc } else { &sockets.mc };
                match discovery::recv(sock).await {
                    Ok((from, packets)) => {
                        for packet in packets {
                            if ingress
                                .send(Input::Discovery { from, packet })
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(e) => err!(log, if_name, "discovery recv: {e}"),
                }
            }
        })
    }

    fn start_server(&mut self) -> bool {
        // Release the old bind before taking the new one; both want the same
        // address and port.
        self.server = None;

        let Some(peer) = self.sm.status().peer else {
            return false;
        };

        let context = ServerContext {
            db: self.ctx.db.clone(),
            hostname: self.ctx.hostname.clone(),
            kind: self.ctx.config.kind,
            peer: peer.addr,
            ingress: self.ingress.clone(),
        };

        match exchange::start_server(
            context,
            self.ctx.config.addr,
            self.ctx.config.exchange_port,
            &self.ctx.config.if_name,
            &self.ctx.log,
        ) {
            Ok(server) => {
                self.server = Some(server);
                true
            }
            Err(e) => {
                wrn!(
                    self.ctx.log,
                    self.ctx.config.if_name,
                    "exchange handler start: {e}"
                );
                false
            }
        }
    }

    fn sockets(&self) -> Option<&Sockets> {
        self.discovery.as_ref().map(|d| &*d.sockets)
    }

    fn endpoint(&self, addr: Ipv6Addr) -> Endpoint {
        Endpoint {
            addr,
            if_index: self.ctx.config.if_index,
            port: self.ctx.config.exchange_port,
        }
    }

    /// Republish what the admin API and oximeter read.
    ///
    /// These are the mutable shared structures the threaded implementation
    /// wrote to as it went; the core owns the values now and this copies them
    /// out.
    fn publish(&self) {
        let status = self.sm.status();
        let iface = &self.ctx.iface;

        if *lock!(iface.fsm_state) != status.state {
            iface.transition(status.state.clone());
        }
        // The core forgets its addressing while waiting for an address; the
        // last known interface name stays published so metrics keep their
        // label, matching the threaded implementation.
        if status.if_index != 0 {
            iface.set_if_info(status.if_index, status.if_name);
        }
        *lock!(iface.peer_identity) = status.peer;

        let c = self.sm.counters();
        let s = &self.ctx.stats;
        s.solicitations_sent
            .store(c.solicitations_sent, Ordering::Relaxed);
        s.solicitations_received
            .store(c.solicitations_received, Ordering::Relaxed);
        s.advertisements_sent
            .store(c.advertisements_sent, Ordering::Relaxed);
        s.advertisements_received
            .store(c.advertisements_received, Ordering::Relaxed);
        s.peer_expirations
            .store(c.peer_expirations, Ordering::Relaxed);
        s.peer_address_changes
            .store(c.peer_address_changes, Ordering::Relaxed);
        s.peer_established
            .store(c.peer_established, Ordering::Relaxed);
        s.updates_sent.store(c.updates_sent, Ordering::Relaxed);
        s.updates_received
            .store(c.updates_received, Ordering::Relaxed);
        s.update_send_fail
            .store(c.update_send_fail, Ordering::Relaxed);
    }
}

/// The discovery sockets plus the tasks reading them. Dropping this stops the
/// readers and closes the sockets, which is how the driver honors
/// [`Action::CloseSockets`].
struct Discovery {
    sockets: Arc<Sockets>,
    readers: Vec<JoinHandle<()>>,
}

impl Drop for Discovery {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}
