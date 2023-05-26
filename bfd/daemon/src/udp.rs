use anyhow::Result;
use bfd::{bidi, packet};
use slog::{error, warn, Logger};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;

/// Port to be used for BFD multihop per RFC 5883.
const BFD_MULTIHOP_PORT: u16 = 4784;

/// Create a bidirectional chennel linking a peer session to an underlying BFD
/// session over UDP.
pub(crate) fn channel(
    listen: IpAddr,
    peer: IpAddr,
    log: Logger,
) -> Result<bidi::Endpoint<(IpAddr, packet::Control)>> {
    let domain = if listen.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sk = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let sa = SocketAddr::new(listen, BFD_MULTIHOP_PORT).into();
    sk.bind(&sa)?;

    let (local, remote) = bidi::channel();

    ingress(peer, remote.tx, sk.try_clone()?, log.clone());
    egress(remote.rx, sk, log.clone());

    Ok(local)
}

/// Run an egress handler, taking BFD control packets from a session and sending
/// the out to the peer over UDP.
fn egress(rx: Receiver<(IpAddr, packet::Control)>, sk: Socket, log: Logger) {
    spawn(move || loop {
        let (addr, pkt) = match rx.recv() {
            Ok(result) => result,
            Err(e) => {
                warn!(log, "udp egress channel closed: {e}");
                break;
            }
        };
        let sa = SocketAddr::new(addr, BFD_MULTIHOP_PORT).into();
        if let Err(e) = sk.send_to(&pkt.to_bytes(), &sa) {
            error!(log, "udp send: {e}");
        }
    });
}

/// Run an ingress handler, taking BFD control packets from a remote peer over
/// UDP and sending them to the local peer sesion for handling.
fn ingress(
    peer: IpAddr,
    tx: Sender<(IpAddr, packet::Control)>,
    sk: Socket,
    log: Logger,
) {
    spawn(move || loop {
        //TODO figure out real bound
        let mut buf = [MaybeUninit::new(0); 1024];

        let (n, sa) = match sk.recv_from(&mut buf) {
            Err(e) => {
                error!(log, "udp recv: {e}");
                continue;
            }
            Ok((n, sa)) => (n, sa.as_socket().unwrap()),
        };

        if sa.ip() != peer {
            warn!(
                log,
                "udp message not from peer {} != {peer}, dropping",
                sa.ip(),
            );
            continue;
        }

        // TODO: perhaps we don't need to use the socket2 crate here - this is
        // all pretty bog-standard UDP. Should probably switch to the UDP
        // machinery in the standard library.
        let ibuf = unsafe { &u8_slice_assume_init_ref(&buf)[..n] };

        let pkt = match packet::Control::wrap(ibuf) {
            Ok(pkt) => pkt,
            Err(e) => {
                error!(log, "parse control packet: {e}");
                continue;
            }
        };

        if let Err(e) = tx.send((sa.ip(), pkt)) {
            warn!(log, "udp ingress channel closed: {e}");
            break;
        }
    });
}

//TODO trade for `MaybeUninit::slice_assume_init_ref` when it becomes available
//in stable Rust.
#[inline(always)]
pub(crate) const unsafe fn u8_slice_assume_init_ref(
    slice: &[MaybeUninit<u8>],
) -> &[u8] {
    unsafe { &*(slice as *const [MaybeUninit<u8>] as *const [u8]) }
}
