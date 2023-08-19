//XXX remove this in favor of broker architecture?

use crate::connection::BgpConnection;
use rdb::types::*;
use rdb::Db;
use sled::Event;
use std::net::Ipv4Addr;
use std::sync::mpsc::{channel, Sender};
use std::thread::spawn;

pub struct Announcer<Cnx: BgpConnection> {
    db: Db,
    #[allow(dead_code)]
    conn: Cnx,
}

pub enum Update {
    AddPrefix4 { prefix: Prefix4, nexthop: Ipv4Addr },
    RemovePrefix4 { prefix: Prefix4, nexthop: Ipv4Addr },
}

impl<Cnx: BgpConnection> Announcer<Cnx> {
    pub fn watch(&self) {
        let (tx, rx) = channel();
        self.run_watchers(tx);

        loop {
            let update = rx.recv().unwrap();
            self.handle_update(update);
        }
    }

    fn handle_update(&self, _update: Update) {
        todo!();
    }

    fn run_watchers(&self, tx: Sender<Update>) {
        let db = self.db.clone();
        let tx = tx.clone();
        spawn(move || Self::watch_nexthop(db, tx));
    }

    fn watch_nexthop(db: Db, tx: Sender<Update>) {
        let subscriber = db.watch_nexthop().unwrap();
        for event in subscriber.take(1) {
            match event {
                Event::Insert { key, value: _ } => {
                    let key = String::from_utf8_lossy(&key);
                    let key: Route4Key = key.parse().unwrap();
                    tx.send(Update::AddPrefix4 {
                        prefix: key.prefix,
                        nexthop: key.nexthop,
                    })
                    .unwrap();
                }

                Event::Remove { key } => {
                    let key = String::from_utf8_lossy(&key);
                    let key: Route4Key = key.parse().unwrap();
                    tx.send(Update::RemovePrefix4 {
                        prefix: key.prefix,
                        nexthop: key.nexthop,
                    })
                    .unwrap();
                }
            }
        }
    }
}
