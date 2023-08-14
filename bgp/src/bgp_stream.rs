use crate::error::Error;
use crate::messages::{
    Header, Message, MessageType, NotificationMessage, OpenMessage,
    UpdateMessage,
};
use crate::session::FsmEvent;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::Sender;

pub trait BgpListener<Stream: BgpStream> {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized;
    fn accept(&self) -> Result<(Stream, SocketAddr), Error>;
}

pub trait BgpStream: Sync + Send {
    fn connect(sa: &SocketAddr) -> Result<Self, Error>
    where
        Self: Sized;
    fn send(&mut self, msg: Message) -> Result<(), Error>;
}

pub struct BgpListenerTcp {
    listener: TcpListener,
}

impl BgpListener<BgpStreamTcp> for BgpListenerTcp {
    fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self {
            listener: TcpListener::bind(addr)?,
        })
    }

    fn accept(&self) -> Result<(BgpStreamTcp, SocketAddr), Error> {
        let (conn, sa) = self.listener.accept()?;
        Ok((BgpStreamTcp { conn }, sa))
    }
}

pub struct BgpStreamTcp {
    conn: TcpStream,
}

impl BgpStream for BgpStreamTcp {
    fn connect(_sa: &SocketAddr) -> Result<Self, Error> {
        todo!();
    }
    fn send(&mut self, msg: Message) -> Result<(), Error> {
        let msg_buf = msg.to_wire()?;
        let header = Header {
            length: msg_buf.len() as u16 + 19,
            typ: MessageType::from(&msg),
        };
        let mut header_buf = header.to_wire().to_vec();
        header_buf.extend_from_slice(&msg_buf);
        self.conn.write_all(&header_buf)?;
        Ok(())
    }
}

impl BgpStreamTcp {
    pub fn run_rx_handler(&mut self, s: Sender<FsmEvent<BgpStreamTcp>>) {
        loop {
            let hdr = match self.recv_header() {
                Ok(hdr) => hdr,
                Err(_e) => {
                    //TODO log
                    continue;
                }
            };
            let mut msgbuf = vec![0u8; (hdr.length - 19) as usize];
            self.conn.read_exact(&mut msgbuf).unwrap();

            let msg: Message = match hdr.typ {
                MessageType::Open => match OpenMessage::from_wire(&msgbuf) {
                    Ok(m) => m.into(),
                    Err(_) => continue, //TODO log
                },
                MessageType::Update => {
                    match UpdateMessage::from_wire(&msgbuf) {
                        Ok(m) => m.into(),
                        Err(_) => continue, //TODO log
                    }
                }
                MessageType::Notification => {
                    match NotificationMessage::from_wire(&msgbuf) {
                        Ok(m) => m.into(),
                        Err(_) => continue, //TODO log
                    }
                }
                MessageType::KeepAlive => Message::KeepAlive,
            };
            s.send(FsmEvent::Message(msg)).unwrap();
        }
    }

    fn recv_header(&mut self) -> Result<Header, Error> {
        let mut buf = [0u8; 19];
        let mut i = 0;
        loop {
            let n = self.conn.read(&mut buf[i..])?;
            i += n;
            if i < 19 {
                continue;
            }
            match Header::from_wire(&buf) {
                Ok(h) => return Ok(h),
                Err(_) => continue,
            };
        }
    }
}
