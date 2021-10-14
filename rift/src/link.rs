// Copyright 2021 Oxide Computer Company

use crate::{runtime_error, config::Config};
use std::net::Ipv6Addr;
use rift_protocol::{lie::{LIEPacket, Neighbor}, Header};
use crate::error::Error;
use crate::{
    Peer,
    PeerEvent,
};
use platform::{
    Platform,
    IpIfAddr,
    LinkState,
};
use std::time::{Duration, SystemTime};
use slog::{info, debug, error, trace, warn};
use std::hash::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use icmpv6::{RDPMessage, RouterAdvertisement, RouterSolicitation};
use std::marker::{Send, Sync};
use tokio::{
    spawn, 
    select,
    time::sleep,
    task::JoinHandle,
    sync::{Mutex, broadcast, mpsc::{Sender, Receiver}},
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum State {
    WaitForCarrier,
    WaitForV6ll,
    Solicit,
    OneWay,
    TwoWay,
    ThreeWay,
}

#[derive(Debug, Copy, Clone)]
pub enum Event {
    LinkDown,
    AddressLost,
    PeerExpired,
}

pub struct LinkSM {
    pub state: Arc::<Mutex::<LinkSMState>>,
    pub threads: Arc::<Mutex::<Threads>>,
    pub log: slog::Logger,
    pub link_name: String,
}

pub struct Threads {
    carrier: Option<JoinHandle<()>>,
    v6ll: Option<JoinHandle<()>>,
    rdp: Option<JoinHandle<()>>,
    rift: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct LinkSMState {
    pub current: State,
    pub link_state: platform::LinkState,
    pub v6ll: Option::<IpIfAddr>,
    pub peer: Option::<Peer>,
    pub config: Config,
}

macro_rules! loop_continue {
    ($delay:expr) => {
        tokio::time::sleep(std::time::Duration::from_secs($delay)).await;
        continue
    };
}

macro_rules! link_error {
    ($log:expr, $link:expr, $format:expr) => {
        error!($log, "[{}]: {}", $link, $format)
    };
    ($log:expr, $link:expr, $error:expr, $format:expr) => {
        error!($log, "[{}]: {}: {}", $link, $format, $error)
    };
    ($log:expr, $link:expr, $error:expr, $format:expr, $($args:expr)*) => {
        error!($log, "[{}]: {}: {}", 
            $link, format!($format, $($args),*), $error)
    };
}

macro_rules! link_info {
    ($log:expr, $link:expr, $format:expr) => {
        info!($log, "[{}]: {}", $link, $format)
    };
    ($log:expr, $link:expr, $format:expr, $($args:expr)*) => {
        info!($log, "[{}]: {}", $link, format!($format, $($args),*))
    };
}

macro_rules! link_debug {
    ($log:expr, $link:expr, $format:expr) => {
        debug!($log, "[{}]: {}", $link, $format)
    };
    ($log:expr, $link:expr, $format:expr, $($args:expr)*) => {
        debug!($log, "[{}]: {}", $link, format!($format, $($args),*))
    };
}

macro_rules! link_trace {
    ($log:expr, $link:expr, $format:expr) => {
        trace!($log, "[{}]: {}", $link, $format)
    };
    ($log:expr, $link:expr, $format:expr, $($args:expr)*) => {
        trace!($log, "[{}]: {}", $link, format!($format, $($args),*))
    };
}

macro_rules! link_warn {
    ($log:expr, $link:expr, $format:expr) => {
        warn!($log, "[{}]: {}", $link, $format)
    };
    ($log:expr, $link:expr, $format:expr, $($args:expr)*) => {
        warn!($log, "[{}]: {}", $link, format!($format, $($args),*))
    };
}

const QUANTUM: u64 = 1;

// LinkSM implementation ......................................................

impl LinkSM {

    pub(crate) fn new(
        log: slog::Logger,
        name: String,
        link_state: platform::LinkState,
        config: Config,
    ) -> Self {
        LinkSM{
            log: log,
            link_name: name,
            threads: Arc::new(Mutex::new(Threads {
                carrier: None,
                v6ll: None,
                rdp: None,
                rift: None,
            })),
            state: Arc::new(Mutex::new(LinkSMState {
                current: match link_state {
                    platform::LinkState::Down => State::WaitForCarrier,
                    platform::LinkState::Unknown => State::WaitForCarrier,
                    platform::LinkState::Up => State::WaitForV6ll,
                },
                link_state: LinkState::Unknown,
                peer: None,
                v6ll: None,
                config: config,
            })),
        }
    }

    pub(crate) async fn run<P: Platform + Send + Sync + 'static>(
        &mut self, 
        platform: Arc::<Mutex::<P>>,
        peer_event_tx: broadcast::Sender<PeerEvent>,
    ) {

        // clone stuff to move into thread
        let log = self.log.clone();
        let state = self.state.clone();
        let link_name = self.link_name.clone();
        let threads = self.threads.clone();
        let p = platform.clone();

        let mut t = self.threads.lock().await;
        t.carrier = Some(spawn(async move {
            Self::carrier_sm(
                &p,
                &log,
                &link_name,
                &state,
                &threads,
                peer_event_tx).await;
        }));

    }

    async fn carrier_sm<P: Platform + Send + Sync + 'static>(
        platform: &Arc::<Mutex::<P>>,
        log: &slog::Logger,
        link_name: &String,
        state: &Arc::<Mutex::<LinkSMState>>,
        threads: &Arc::<Mutex::<Threads>>,
        peer_event_tx: broadcast::Sender<PeerEvent>,
    ) {

        let (event_tx, _) = broadcast::channel(32);

        loop {
            link_trace!(log, link_name, "checking for carrier");

            // get the current link status from the platform
            let link_status = {
                let p = platform.lock().await;
                match p.get_link_status(link_name) {
                    Err(e) => {
                        link_error!(log, &link_name, e, "link status");
                        loop_continue!(QUANTUM);
                    }
                    Ok(link_status) => link_status
                }
            };

            // get the last observed link state
            let link_state = {
                let s = state.lock().await;
                s.link_state
            };

            // if the link state has not changed, do nothing
            if link_status.state == link_state {
                loop_continue!(QUANTUM);
            }

            // handle a link state change
            match handle_link_state_change(
                &platform, 
                link_status.state, 
                &state, 
                &threads, 
                &event_tx,
                &log,
                &link_name,
                &peer_event_tx,
            ).await {
                Err(e) => {
                    link_error!(log, &link_name, e, "handle link state change");
                    loop_continue!(QUANTUM);
                }
                Ok(_) => {},
            }

            sleep(Duration::from_secs(QUANTUM)).await;
        }
    }

    async fn v6addr_sm<P: Platform + Send + Sync + 'static>(
        platform: Arc::<Mutex::<P>>,
        log: slog::Logger,
        link_name: String,
        state: Arc::<Mutex::<LinkSMState>>,
        threads: Arc::<Mutex::<Threads>>,
        event_tx: broadcast::Sender<Event>,
        peer_event_tx: broadcast::Sender<PeerEvent>,
    ) {

        link_trace!(log, link_name, "enter v6addr sm");

        let mut event_rx = event_tx.subscribe();

        let quit = Arc::new(AtomicBool::new(false));

        link_trace!(log, link_name, "starting address event loop");

        addr_loop(
            platform.clone(),
            log.clone(),
            link_name.clone(),
            state.clone(),
            threads.clone(),
            event_tx.clone(),
            quit.clone(),
            peer_event_tx.clone(),
        ).await;

        link_trace!(log, link_name, "started address event loop");

        loop {

            let event = match event_rx.recv().await {
                Err(e) => {
                    link_error!(log, &link_name, e, "event recv");
                    loop_continue!(QUANTUM);
                }
                Ok(ls) => ls
            };
            match event {
                Event::LinkDown => {
                    link_warn!(log, link_name, "link lost, exiting v6addr_sm");
                    quit.store(true, Ordering::Relaxed);
                    return
                }
                _ => {}
            }

        }
    }

    async fn solicit<P: Platform + Send + Sync + 'static>(
        platform: Arc::<Mutex::<P>>,
        log: slog::Logger,
        link_name: String,
        state: Arc::<Mutex::<LinkSMState>>,
        threads: Arc::<Mutex::<Threads>>,
        event_tx: broadcast::Sender<Event>,
        peer_event_tx: broadcast::Sender<PeerEvent>,
    ) {

        let mut event_rx = event_tx.subscribe();
        loop {

            link_trace!(log, link_name, "solicit");

            let (v6ll, rdp_rx) = match get_rdp_channel(&state, &platform).await {
                Ok(r) => r,
                Err(e) => {
                    link_error!(log, link_name, e, "get rdp channel");
                    loop_continue!(QUANTUM);
                }
            };

            let quit = Arc::new(AtomicBool::new(false));

            advertise_solicit_tx_loop(
                platform.clone(),
                log.clone(),
                link_name.clone(),
                state.clone(),
                threads.clone(),
                quit.clone(),
                event_tx.clone(),
                v6ll,
            ).await;

            advertise_solicit_rx_loop(
                platform.clone(),
                log.clone(),
                link_name.clone(),
                state.clone(),
                threads.clone(),
                quit.clone(),
                event_tx.clone(),
                rdp_rx,
                peer_event_tx.clone(),
            ).await;

            loop {

                // listen for an event, in the case that the link
                // carrier goes away, stop the v6addr_sm, we'll get
                // re-launched by carrier_sm in the event that the link comes
                // back up
                let event = match event_rx.recv().await {
                    Err(e) => {
                        link_error!(log, &link_name, e, "solicit: event recv");
                        loop_continue!(QUANTUM);
                    }
                    Ok(state) => state
                };

                link_trace!(log, link_name, "solicit: event received");
                match event {
                    Event::LinkDown => {
                        link_warn!(log, link_name, "link lost exiting solicit");
                        quit.store(true, Ordering::Relaxed);
                        return
                    }
                    _ => {}
                }

            }
        }
    }

    async fn lie_entry<P: Platform + Send + Sync + 'static>(
        platform: Arc::<Mutex::<P>>,
        log: slog::Logger,
        link_name: String,
        state: Arc::<Mutex::<LinkSMState>>,
        threads: Arc::<Mutex::<Threads>>,
        event_tx: broadcast::Sender<Event>,
        peer_event_tx: broadcast::Sender<PeerEvent>,
    ) {

        let quit = Arc::new(AtomicBool::new(false));

        let (local_addr, local_ifx, peer_addr) = {
            let mut s = state.lock().await;
            match (s.v6ll, s.peer.as_ref()) {
                (Some(v6ll), Some(peer)) => (v6ll.addr, v6ll.if_index, peer.remote_addr),
                _ => {
                    link_warn!(log, link_name, 
                        "cannot begin one-way adjacency without local and peer address");
                    let mut t = threads.lock().await;
                    s.current = State::Solicit;
                    t.rift = None;
                    return;
                }
            }
        };

        let (tx, rx) = get_link_channel(&log, &link_name, &platform, local_addr, peer_addr, local_ifx).await;

        one_way_loop(
            log.clone(), 
            link_name.clone(), 
            state.clone(),
            threads.clone(), 
            quit.clone(),
            tx,
            rx,
            peer_event_tx.clone(),
        );

        let mut event_rx = event_tx.subscribe();

        loop {

            let event = match event_rx.recv().await {
                Err(e) => {
                    link_error!(log, &link_name, e, "event recv");
                    loop_continue!(QUANTUM);
                }
                Ok(state) => state
            };

            link_trace!(log, link_name, "rift: event received");
            match event {
                Event::LinkDown => {
                    link_warn!(log, link_name, "link lost exiting rift");
                    quit.store(true, Ordering::Relaxed);
                    return
                }
                Event::PeerExpired => {
                    link_warn!(log, link_name, "peer expired exiting rift");
                    quit.store(true, Ordering::Relaxed);
                    return
                }
                _ => {}
            }


        }
    }

}

// LinkSM trait implementations ...............................................

impl Hash for LinkSM {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.link_name.hash(state);
    }
}

impl PartialEq for LinkSM {
    fn eq(&self, other: &Self) -> bool {
        if self == other { return true };

        self.link_name == other.link_name
    }
}
impl Eq for LinkSM {}

// Helpers ....................................................................

async fn get_rdp_channel<P: Platform>(
    state: &Arc::<Mutex::<LinkSMState>>, 
    platform: &Arc::<Mutex::<P>>,
) -> Result<(IpIfAddr, Receiver<RDPMessage>), Error> {

    let v6ll = {
        let s = state.lock().await;
        match s.v6ll {
            None => return runtime_error!("cannot rdp without v6ll"),
            Some(v6ll) => v6ll
        }
    };

    let rx = {
        let p = platform.lock().await;
        match p.get_rdp_channel(Some(v6ll)) {
            Err(e) => return runtime_error!("get rdp channel: {}", e),
            Ok(rx) => rx
        }
    };

    Ok((v6ll, rx))

}

async fn advertise_solicit_tx_loop<P: Platform + Send + 'static>(
    platform: Arc::<Mutex::<P>>,
    log: slog::Logger,
    link_name: String,
    state: Arc::<Mutex::<LinkSMState>>,
    threads: Arc::<Mutex::<Threads>>,
    quit: Arc::<AtomicBool>,
    event_tx: broadcast::Sender<Event>,
    v6ll: IpIfAddr,
) {

    spawn(async move { loop {

        if quit.load(Ordering::Relaxed) {
            let mut t = threads.lock().await;
            t.rdp = None;
            return;
        }

        match solicit(
            &platform, 
            &log,
            &link_name,
            &state, 
            &threads,
            &event_tx,
            v6ll).await {
            Err(e) => link_error!(log, link_name, e, "solicit"),
            Ok(sent) => {
                if sent {
                    link_trace!(log, link_name, "solicitation sent");
                }
            }
        }

        match advertise(&platform, v6ll).await {
            Err(e) => link_error!(log, link_name, e, "advertise"),
            Ok(sent) => {
                if sent {
                    link_trace!(log, link_name, "advertisement sent");
                }
            }
        }

        // 10x sampling rate
        sleep(Duration::from_secs_f32(QUANTUM as f32 / 10.0f32)).await;
    }});

}

async fn advertise_solicit_rx_loop<P: Platform + Send + Sync + 'static>(
    platform: Arc::<Mutex::<P>>,
    log: slog::Logger,
    link_name: String,
    state: Arc::<Mutex::<LinkSMState>>,
    threads: Arc::<Mutex::<Threads>>,
    quit: Arc::<AtomicBool>,
    event_tx: broadcast::Sender<Event>,
    mut rdp_rx: Receiver<RDPMessage>,
    peer_event_tx: broadcast::Sender<PeerEvent>,
) {

    spawn(async move { loop {
        if quit.load(Ordering::Relaxed) {
            return;
        }
        //TODO recv_timeout
        let msg = match rdp_rx.recv().await {
            None => {
                //TODO exit and close out state for this thead
                link_warn!(log, link_name, "rdp receiver closed");
                loop_continue!(QUANTUM);
            }
            Some(msg) => msg
        };
        let from = match msg.from {
            None => {
                link_warn!(log, link_name, "rdp with no from addr");
                loop_continue!(QUANTUM);
            }
            Some(from) => from
        };

        match msg.packet {
            icmpv6::ICMPv6Packet::RouterSolicitation(s) => {
                handle_rdp_solicit(
                    &platform,
                    &log,
                    &link_name,
                    &state,
                    &threads,
                    &quit,
                    &event_tx,
                    &rdp_rx,
                    from,
                    s,
                ).await
            }

            icmpv6::ICMPv6Packet::RouterAdvertisement(a) => {
                handle_rdp_advertise(
                    &platform,
                    &log,
                    &link_name,
                    &state,
                    &threads,
                    &quit,
                    &event_tx,
                    &rdp_rx,
                    from,
                    a,
                    &peer_event_tx,
                ).await
            }
        }

        // 10x sampling rate
        sleep(Duration::from_secs_f32(QUANTUM as f32 / 10.0f32)).await;
    }});

}

fn one_way_loop(
    log: slog::Logger,
    link_name: String,
    state: Arc::<Mutex::<LinkSMState>>,
    threads: Arc::<Mutex::<Threads>>,
    quit: Arc::<AtomicBool>,
    tx: Sender<LIEPacket>,
    mut rx: Receiver<LIEPacket>,
    peer_event_tx: broadcast::Sender<PeerEvent>,
) {

    spawn(async move {
        link_trace!(log, link_name, "enter one way loop");
        loop {


            if quit.load(Ordering::Relaxed) {
                let mut t = threads.lock().await;
                t.rift = None;
                break;
            }

            let tx_msg = match create_lie_packet(&log, &link_name, &state).await {
                Err(e) => {
                    link_error!(log, link_name, e, "create LIE packet");
                    loop_continue!(QUANTUM);
                }
                Ok(msg) => msg,
            };

            select! {

                // handle transmit
                tx_result = tx.send(tx_msg) => {
                    match tx_result {
                        Err(e) => link_error!(log, link_name, e, "one-way: link-info send"),
                        Ok(_) => link_trace!(log, link_name, "one-way: link-info sent"),
                    }
                    sleep(Duration::from_secs(QUANTUM)).await;
                }

                // handle receive
                rx_result = rx.recv() => {

                    match rx_result {
                        None => {
                            link_warn!(log, link_name, "one-way: LIE channel closed");
                            break;
                        },
                        Some(msg) => {
                            link_trace!(log, link_name, "one-way: {:#?}", msg);
                            let mut s = state.lock().await;
                            match &mut s.peer {
                                None => {
                                    // We should get kicked out of this loop by the quit atomic
                                    // being set on the next iteration
                                    link_warn!(log, link_name, "in one-way state with no peer");
                                }
                                Some(ref mut p) => {
                                    p.lie = Some(msg.clone());
                                    p.neighbor = Some(Neighbor{
                                        originator: msg.header.sender,
                                        remote_id: msg.local_id,
                                    });
                                    s.current = State::TwoWay;
                                    drop(s);
                                    two_way_loop(
                                        &log,
                                        &link_name,
                                        &state,
                                        &threads,
                                        &quit,
                                        &tx,
                                        &mut rx,
                                        &peer_event_tx,
                                    ).await;
                                    loop_continue!(QUANTUM);
                                }
                            }
                        }
                    }

                }

            };

        }
    });

}

async fn two_way_loop(
    log: &slog::Logger,
    link_name: &String,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    quit: &Arc::<AtomicBool>,
    tx: &Sender<LIEPacket>,
    rx: &mut Receiver<LIEPacket>,
    peer_event_tx: &broadcast::Sender<PeerEvent>,
) {

    link_trace!(log, link_name, "enter two way loop");
    loop {

        if quit.load(Ordering::Relaxed) {
            let mut t = threads.lock().await;
            t.rift = None;
            break;
        }

        let tx_msg = match create_lie_packet(&log, &link_name, &state).await {
            Err(e) => {
                link_error!(log, link_name, e, "create LIE packet");
                loop_continue!(QUANTUM);
            }
            Ok(msg) => msg,
        };

        select! {

            // handle transmit
            tx_result = tx.send(tx_msg) => {
                match tx_result {
                    Err(e) => link_error!(log, link_name, e, "two-way: link-info send"),
                    Ok(_) => link_trace!(log, link_name, "two-way: link-info sent"),
                }
                sleep(Duration::from_secs(QUANTUM)).await;
            }

            // handle receive
            rx_result = rx.recv() => {

                match rx_result {
                    None => {
                        link_warn!(log, link_name, "two-way LIE channel closed");
                        break;
                    }
                    Some(msg) => {
                        link_trace!(log, link_name, "two-way: {:#?}", msg);
                        let mut s = state.lock().await;

                        let link_id = match s.v6ll {
                            None => {
                                drop(s);
                                link_warn!(log, link_name, "two-way: no v6ll address");
                                loop_continue!(QUANTUM);
                            }
                            Some(v6ll) => v6ll.if_index,
                        };
                        // check for valid reflection
                        if msg.neighbor.originator == s.config.id && 
                           msg.neighbor.remote_id == link_id as u32 {
                               s.current = State::ThreeWay;
                               drop(s);
                               link_debug!(log, link_name, 
                                   "valid reflection, transitioning to three-way adjacency");
                               three_way_loop(
                                   log,
                                   link_name,
                                   state,
                                   threads,
                                   quit,
                                   tx,
                                   rx,
                                   peer_event_tx,
                               ).await;
                               loop_continue!(QUANTUM);
                        } else {
                            link_warn!(log, link_name, 
                                "invalid reflection: {:#?} returning to one-way", msg.neighbor);
                            s.current = State::OneWay;
                            return;
                        }
                    }
                }

            }

        }

        sleep(Duration::from_secs(QUANTUM)).await;

    }

}

async fn three_way_loop(
    log: &slog::Logger,
    link_name: &String,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    quit: &Arc::<AtomicBool>,
    tx: &Sender<LIEPacket>,
    rx: &mut Receiver<LIEPacket>,
    peer_event_tx: &broadcast::Sender<PeerEvent>,
) {

    link_trace!(log, link_name, "enter three way loop");

    let (peer, local_if) = {
        let state = state.lock().await;
        let peer = match &state.peer {
            None => {
                link_error!(log, link_name, "in three-way with no peer");
                return;
            }
            Some(p) => p.clone(),
        };
        let v6ll = match state.v6ll {
            None => {
                link_error!(log, link_name, "in three-way with no v6ll");
                return;
            }
            Some(a) => a,
        };
        (peer, v6ll)
    };

    //send peer up event
    match peer_event_tx.send(PeerEvent::Up((peer.clone(), local_if))) {
        Ok(_) => {}
        Err(e) => {
            link_error!(log, link_name, "send link up event: {}", e);
            return;
        }
    };

    loop {

        if quit.load(Ordering::Relaxed) {
            let mut t = threads.lock().await;
            t.rift = None;

            //send peer down event
            match peer_event_tx.send(PeerEvent::Down((peer, local_if))) {
                Ok(_) => {}
                Err(e) => {
                    link_error!(log, link_name, "send link up event: {}", e);
                    return;
                }
            };

            break;
        }

        //TODO mostly copy pasta from two_way
        
        let tx_msg = match create_lie_packet(&log, &link_name, &state).await {
            Err(e) => {
                link_error!(log, link_name, e, "create LIE packet");
                loop_continue!(QUANTUM);
            }
            Ok(msg) => msg,
        };

        select! {

            // handle transmit
            tx_result = tx.send(tx_msg) => {
                match tx_result {
                    Err(e) => link_error!(log, link_name, e, "three-way: link-info send"),
                    Ok(_) => link_trace!(log, link_name, "three-way: link-info sent"),
                }
                sleep(Duration::from_secs(QUANTUM)).await;
            }

            // handle receive
            rx_result = rx.recv() => {

                match rx_result {
                    None => {
                        link_warn!(log, link_name, "three-way LIE channel closed");

                        //send peer down event
                        match peer_event_tx.send(PeerEvent::Down((peer, local_if))) {
                            Ok(_) => {}
                            Err(e) => {
                                link_error!(log, link_name, "send link up event: {}", e);
                                return;
                            }
                        };

                        break;
                    }
                    Some(msg) => {
                        link_trace!(log, link_name, "three-way: {:#?}", msg);
                        let mut s = state.lock().await;

                        let link_id = match s.v6ll {
                            None => {
                                drop(s);
                                link_warn!(log, link_name, "three-way: no v6ll address");
                                loop_continue!(QUANTUM);
                            }
                            Some(v6ll) => v6ll.if_index,
                        };
                        // check for valid reflection
                        if msg.neighbor.originator == s.config.id && 
                           msg.neighbor.remote_id == link_id as u32 {
                               drop(s);
                               link_debug!(log, link_name, 
                                   "valid reflection, remaining in three-way adjacency");
                               // nothing to do, we're already here
                               loop_continue!(QUANTUM);
                        } else {
                            link_warn!(log, link_name, 
                                "invalid reflection: {:#?} returning to two-way", msg.neighbor);
                            s.current = State::TwoWay;

                            //send peer down event
                            match peer_event_tx.send(PeerEvent::Down((peer, local_if))) {
                                Ok(_) => {}
                                Err(e) => {
                                    link_error!(log, link_name, "send link up event: {}", e);
                                    return;
                                }
                            };

                            return;
                        }
                    }
                }

            }

        }

        sleep(Duration::from_secs(QUANTUM)).await;

    }

}

async fn create_lie_packet(
    log: &slog::Logger,
    link_name: &String,
    state: &Arc::<Mutex::<LinkSMState>>,
) -> Result<LIEPacket, Error> {

    let s = state.lock().await;
    let (router_id, link_id, level) = {
        let link_id = match s.v6ll {
            None => {
                return runtime_error!("no local address")
            }
            Some(v6ll) => v6ll.if_index,
        };
        (s.config.id, link_id, s.config.level)
    };

    let nbr = {
        match &s.peer {
            None => Neighbor::default(),
            Some(p) => {
                match &p.neighbor {
                    None => Neighbor::default(),
                    Some(nbr) => *nbr,
                }
            }
        }
    };

    Ok(LIEPacket{
        header: Header {
            sender: router_id,
            level: level,
            ..Default::default()
        },
        local_id: link_id as u32,
        name: {
            match hostname::get() {
                Ok(n) => match n.into_string() {
                    Ok(s) => s,
                    Err(_) => {
                        link_warn!(log, link_name, "hostname to string");
                        "".to_string()
                    }
                },
                Err(e) => {
                    link_error!(log, link_name, e, "get hostname");
                    "".to_string()
                }
            }
        },
        neighbor: nbr,
        ..Default::default()
    })
}

async fn get_link_channel<P: Platform + Send + Sync + 'static>(
    log: &slog::Logger,
    link_name: &String,
    platform: &Arc::<Mutex::<P>>,
    local_addr: Ipv6Addr,
    peer_addr: Ipv6Addr,
    local_ifx: i32,
) -> (Sender<LIEPacket>, Receiver<LIEPacket>) {

    loop {
        let resp = {
            let p = platform.lock().await;
            p.get_link_channel(local_addr, peer_addr, local_ifx)
        };
        match resp {
            Err(e) => {
                link_error!(log, link_name, e, "get link channel");
                loop_continue!(QUANTUM);
            }
            Ok((tx, rx)) => return (tx, rx),
        }
    }

}

async fn addr_loop<P: Platform + Send + Sync + 'static>(
    platform: Arc::<Mutex::<P>>,
    log: slog::Logger,
    link_name: String,
    state: Arc::<Mutex::<LinkSMState>>,
    threads: Arc::<Mutex::<Threads>>,
    event_tx: broadcast::Sender<Event>,
    quit: Arc::<AtomicBool>,
    peer_event_tx: broadcast::Sender<PeerEvent>,
) {

    let _log = log.clone();

    spawn(async move { loop {

        link_trace!(_log, &link_name, "checking for v6ll");

        if quit.load(Ordering::Relaxed) {
            link_trace!(_log, &link_name, "quitting for v6 addr loop");
            let mut t = threads.lock().await;
            t.v6ll = None;
            return;
        }

        let resp = {
            let p = platform.lock().await;
            p.get_interface_v6ll(link_name.clone())
        };

        let v6ll = match resp {
            Err(e) => {
                link_error!(_log, link_name, e, "get v6ll");
                loop_continue!(QUANTUM);
            },
            Ok(None) => {
                link_debug!(_log, link_name, "no v6ll");
                loop_continue!(QUANTUM);
            }
            Ok(Some(v6ll)) => v6ll
        };

        addr_check(
            &platform,
            &_log,
            &state,
            &threads,
            &link_name,
            &event_tx,
            v6ll,
            &peer_event_tx).await;

        sleep(Duration::from_secs(QUANTUM)).await;
    }});

}

async fn addr_check<P: Platform + Send + Sync + 'static>(
    platform: &Arc::<Mutex::<P>>,
    log: &slog::Logger,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    link_name: &String,
    event_tx: &broadcast::Sender<Event>,
    v6ll: IpIfAddr,
    peer_event_tx: &broadcast::Sender<PeerEvent>,
) {

    let mut s = state.lock().await ;
    match s.v6ll {
        Some(current_v6ll) => {
            if v6ll != current_v6ll {
                link_info!(log, link_name, "using v6ll: {:?}", v6ll);
                s.v6ll = Some(v6ll);
            }
        }
        None => {
            link_info!(log, link_name, "using v6ll: {:?}", v6ll);
            s.v6ll = Some(v6ll);
        }
    }

    let mut t = threads.lock().await;
    match t.rdp {
        None => {
            link_debug!(log, link_name, "launching rdp thread");
            s.current = State::Solicit;
            drop(s);
            let platform_ = platform.clone();
            let log_ = log.clone();
            let link_ = link_name.clone();
            let state_ = state.clone();
            let threads_ = threads.clone();
            let event_tx_ = event_tx.clone();
            let peer_event_tx_ = peer_event_tx.clone();
            t.rdp = Some(spawn(async move { LinkSM::solicit(
                        platform_,
                        log_,
                        link_,
                        state_,
                        threads_,
                        event_tx_,
                        peer_event_tx_,
            ).await}));
        }
        Some(_) => {
            //TODO handle address change
        }
    };
}

async fn handle_link_state_change<P: Platform + Send + Sync + 'static>(
    platform: &Arc::<Mutex::<P>>,
    link_state: LinkState,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    event_tx: &broadcast::Sender<Event>,
    log: &slog::Logger,
    link_name: &String,
    peer_event_tx: &broadcast::Sender<PeerEvent>,
) -> Result<(), Error> {

    match link_state {

        LinkState::Up => handle_link_up(
            platform,
            link_state,
            state, threads,
            event_tx,
            log,
            link_name,
            peer_event_tx,
         ).await,

        _ => handle_link_down(
            state,
            threads,
            event_tx,
            log,
            link_name).await,
    }

}

async fn handle_link_down(
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    event_tx: &broadcast::Sender<Event>,
    log: &slog::Logger,
    link_name: &String,
) -> Result<(), Error> {

    // emit link down signal

    link_debug!(log, link_name, "link lost, emitting link-down event");
    match event_tx.send(Event::LinkDown) {
        Err(e) => return runtime_error!("event send: {}", e),
        Ok(_) => {}
    }

    // wait for dependent threads to stop

    loop {
        let ready = {
            let t = threads.lock().await;
            t.rdp.is_none() && t.v6ll.is_none() && t.rift.is_none()
        };
        if !ready {
            link_debug!(log, &link_name, 
                "waiting for address, rdp and rift threads to stop");
            loop_continue!(QUANTUM);
        }
        let mut s = state.lock().await; 
        match s.current {
            // nothing to do, already here
            State::WaitForCarrier => break,
            _ => {
                s.current = State::WaitForCarrier;
                s.peer = None;
                s.v6ll = None;
                s.link_state = LinkState::Down;
                link_debug!(log, &link_name, "address and rdp threads stopped");
                break;
            }
        }
    }

    Ok(())

}

async fn handle_peer_lost(
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    event_tx: &broadcast::Sender<Event>,
    log: &slog::Logger,
    link_name: &String,
) {

    link_debug!(log, link_name, "peer lost, emitting peer-lost event");
    match event_tx.send(Event::PeerExpired) {
        Err(e) => {
            //TODO better handling
            link_error!(log, link_name, e, "peer lost event send");
        }
        Ok(_) => {}
    }

    //TODO mostly copy-pasta from handle_link_down
    loop {
        let ready = {
            let t = threads.lock().await;
            t.rift.is_none()
        };
        if !ready {
            link_debug!(log, &link_name, "waiting for rift thread to stop");
            loop_continue!(QUANTUM);
        }
        let mut s = state.lock().await;
        match s.current {
            // nothing to do, already here
            State::Solicit => break,
            _ => {
                s.current = State::Solicit;
                s.peer = None;
                link_debug!(log, &link_name, "rift thread stopped");
                break;
            }
        }
    }

}

async fn handle_link_up<P: Platform + Send + Sync + 'static>(
    platform: &Arc::<Mutex::<P>>,
    link_state: LinkState,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    event_tx: &broadcast::Sender<Event>,
    log: &slog::Logger,
    link_name: &String,
    peer_event_tx: &broadcast::Sender<PeerEvent>,
) -> Result<(), Error> {

    link_trace!(log, link_name, "handling link up");

    let mut t = threads.lock().await;
    match t.v6ll {
        None => {
            if link_state == LinkState::Up {
                let mut s = state.lock().await;
                s.link_state = link_state;
                s.current = State::WaitForV6ll;
                t.v6ll = Some(launch_v6addr_sm_thread(
                    platform.clone(),
                    log.clone(),
                    link_name.clone(),
                    state.clone(),
                    threads.clone(),
                    event_tx.clone(),
                    peer_event_tx.clone(),
                ).await)
            }

        }
        Some(_) => { }
    }

    Ok(())

}

async fn launch_v6addr_sm_thread<P: Platform + Send + Sync + 'static>(
    platform: Arc::<Mutex::<P>>,
    log: slog::Logger,
    link_name: String,
    state: Arc::<Mutex::<LinkSMState>>,
    threads: Arc::<Mutex::<Threads>>,
    event_tx: broadcast::Sender<Event>,
    peer_event_tx: broadcast::Sender<PeerEvent>,
) -> JoinHandle<()>  {

    let _log = log.clone();
    let _link_name = link_name.clone();

    link_trace!(log, link_name, "launching v6addr sm thread");

    spawn(async move { LinkSM::v6addr_sm(
            platform,
            _log,
            _link_name,
            state,
            threads,
            event_tx,
            peer_event_tx,
    ).await})

}

async fn handle_rdp_solicit<P: Platform + Send + Sync + 'static>(
    platform: &Arc::<Mutex::<P>>,
    log: &slog::Logger,
    link_name: &String,
    state: &Arc::<Mutex::<LinkSMState>>,
    _threads: &Arc::<Mutex::<Threads>>,
    _quit: &Arc::<AtomicBool>,
    _event_tx: &broadcast::Sender<Event>,
    _rdp_rx: &Receiver<RDPMessage>,
    from: Ipv6Addr,
    _s: RouterSolicitation,
) {

    link_trace!(log, link_name, 
        "received rdp solicitation msg from {:?}", from);

    let v6ll = {
        let s = state.lock().await;
        match s.v6ll {
            None => {
                link_warn!(log, link_name, "cannot solicit without v6ll");
                return;
            }
            Some(v6ll) => v6ll
        }
    };

    match do_advertise(platform, v6ll).await {
        Err(e) => link_error!(log, link_name, e, "advertise solicit response"),
        Ok(_) => {
            link_trace!(log, link_name, 
                "solicitation response sent to {:?}", from)
        }
    }
}

async fn handle_rdp_advertise<P: Platform + Send + Sync + 'static>(
    platform: &Arc::<Mutex::<P>>,
    log: &slog::Logger,
    link_name: &String,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    _quit: &Arc::<AtomicBool>,
    event_tx: &broadcast::Sender<Event>,
    _rdp_rx: &Receiver<RDPMessage>,
    from: Ipv6Addr,
    a: RouterAdvertisement,
    peer_event_tx: &broadcast::Sender<PeerEvent>,
) {

    link_trace!(log, link_name, 
        "received rdp advertisement msg from {:?}", from);

    let rift_running = {
        let t = threads.lock().await;
        match t.rift {
            None => false,
            Some(_) => true,
        }
    };

    let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_millis(),
        Err(e) => {
            link_error!(log, link_name, e, "get duration since unix epoch");
            0
        }
    };
    match rift_running {
        false => {
            link_info!(log, link_name, "adding peer {:?}", from);
            {
                let mut s = state.lock().await;
                s.peer = Some(Peer{
                    remote_addr: from,
                    advertisement: a,
                    last_seen: now,
                    lie: None,
                    neighbor: None,
                });
                s.current = State::OneWay;
            }

            //TODO pack this up into a thread launching function
            let __platform = platform.clone();
            let __log = log.clone();
            let __link = link_name.clone();
            let __state = state.clone();
            let __threads = threads.clone();
            let __event_tx = event_tx.clone();
            let mut t = threads.lock().await;
            let __peer_event_tx = peer_event_tx.clone();
            t.rift = Some(spawn(async move { LinkSM::lie_entry(
                        __platform,
                        __log,
                        __link,
                        __state,
                        __threads,
                        __event_tx,
                        __peer_event_tx,
            ).await}));
        }
        true => {
            let mut s = state.lock().await;
            match s.peer {
                None => {
                    s.peer = Some(Peer{
                        remote_addr: from,
                        advertisement: a,
                        last_seen: now,
                        lie: None,
                        neighbor: None,
                    });
                }
                Some(ref mut p) => {
                    // TODO handle changed peer
                    link_trace!(
                        log, link_name, "peer keepalive {}", p.remote_addr);
                    p.last_seen = now;
                }
            }
        }
    }

}

async fn solicit<P: Platform + Send + 'static>(
    platform: &Arc::<Mutex::<P>>,
    log: &slog::Logger,
    link_name: &String,
    state: &Arc::<Mutex::<LinkSMState>>,
    threads: &Arc::<Mutex::<Threads>>,
    event_tx: &broadcast::Sender<Event>,
    v6ll: IpIfAddr,
) -> Result<bool, Error> {

    let peer = {
        let s = state.lock().await;
        s.peer.clone()
    };
    match peer {
        None => match do_solicit(platform, v6ll).await {
            Err(e) => Err(e),
            Ok(_) => Ok(true),
        },
        Some(p) => {
            let expired = match p.is_expired() {
                Err(e) => return Err(e),
                Ok(expired) => expired
            };
            if !expired {
                // nothing to do
                return Ok(false)
            }
            {
                let mut s = state.lock().await;
                s.peer = None;
            }
            handle_peer_lost(
                state,
                threads,
                event_tx,
                log,
                link_name,
            ).await;
            match do_solicit(platform, v6ll).await {
                Err(e) => Err(e),
                Ok(_) => Ok(true),
            }
        }
    }

}

async fn advertise<P: Platform + Send + 'static>(
    platform: &Arc::<Mutex::<P>>,
    v6ll: IpIfAddr,
) -> Result<bool, Error> {

    //TODO advertise conditions?

    match do_advertise(platform, v6ll).await {
        Err(e) => Err(e),
        Ok(_) => Ok(true),
    }

}

async fn do_solicit<P: Platform + Send + 'static>(
    platform: &Arc::<Mutex::<P>>,
    v6ll: IpIfAddr,
) -> Result<(), Error> {

    let p = platform.lock().await;
    match p.solicit_rift_routers(Some(v6ll)) {
        Err(e) => return runtime_error!("solicit: {}", e),
        Ok(()) => return Ok(())
    }

}

async fn do_advertise<P: Platform + Send + 'static>(
    platform: &Arc::<Mutex::<P>>,
    v6ll: IpIfAddr,
) -> Result<(), Error> {

    let p = platform.lock().await;
    match p.advertise_rift_router(Some(v6ll)) {
        Err(e) => return runtime_error!("advertise: {}", e),
        Ok(()) => return Ok(())
    }

}
