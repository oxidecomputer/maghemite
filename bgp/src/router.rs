use crate::session::FsmEvent;
use std::collections::BTreeMap;
use std::net::IpAddr;
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;

pub struct Dispatcher {
    pub listen: String,
    pub addr_to_session: Mutex<BTreeMap<IpAddr, Sender<FsmEvent>>>,
}

impl Dispatcher {
    pub fn new(listen: String) -> Dispatcher {
        Dispatcher {
            listen,
            addr_to_session: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn run(&self) {
        loop {
            let listener = TcpListener::bind(&self.listen).await.unwrap();
            let (stream, addr) = listener.accept().await.unwrap();
            match self.addr_to_session.lock().await.get(&addr.ip()) {
                Some(tx) => {
                    tx.send(FsmEvent::Connected(stream)).await.unwrap();
                }
                None => continue,
            }
        }
    }
}
