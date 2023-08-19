use crate::messages::UpdateMessage;
use rdb::types::*;
use rdb::Db;
use std::sync::mpsc::{channel, Receiver, Sender};

pub struct Broker {
    _db: Db,
    subscribers4: Vec<Subscriber4>,
}

impl Broker {
    pub fn subscribe4(
        &mut self,
        include: Vec<Prefix4>,
        exclude: Vec<Prefix4>,
    ) -> (Sender<UpdateMessage>, Receiver<UpdateMessage>) {
        let (tx_to_sub, rx_from_broker) = channel();
        let (tx_to_broker, rx_from_sub) = channel();

        self.subscribers4.push(Subscriber4 {
            include,
            exclude,
            rx: rx_from_sub,
            tx: tx_to_sub,
        });

        (tx_to_broker, rx_from_broker)
    }
}

pub struct Subscriber4 {
    pub include: Vec<Prefix4>,
    pub exclude: Vec<Prefix4>,
    pub tx: Sender<UpdateMessage>,
    pub rx: Receiver<UpdateMessage>,
}
