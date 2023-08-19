use crate::connection::BgpConnection;
use crate::error::Error;
use crate::messages::{Prefix, UpdateMessage};
use crate::session::FsmEvent;
use rdb::{Policy, PolicyAction, Prefix4};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::mpsc::Sender;

pub struct Fanout<Cnx: BgpConnection> {
    /// Indexed neighbor address
    egress: BTreeMap<IpAddr, Egress<Cnx>>,
}

//NOTE necessary as #derive is broken for generic types
impl<Cnx: BgpConnection> Default for Fanout<Cnx> {
    fn default() -> Self {
        Self {
            egress: BTreeMap::new(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Rule4 {
    pub prefix: Prefix4,
    pub policy: Policy,
}

impl Rule4 {
    fn matches(&self, prefix: Prefix4) -> bool {
        // To match, the rule must contain the input.
        if prefix.length < self.prefix.length {
            return false;
        }
        if self.prefix.length == 0 {
            return true;
        }
        let a = u32::from(self.prefix.value);
        let b = u32::from(prefix.value);
        let mask = (1 << prefix.length) << (32 - prefix.length);
        (a & mask) == (b & mask)
    }
}

pub struct Egress<Cnx: BgpConnection> {
    pub rules: Vec<Rule4>,
    pub event_tx: Sender<FsmEvent<Cnx>>,
}

impl<Cnx: BgpConnection> Fanout<Cnx> {
    pub fn send(&self, origin: IpAddr, update: &UpdateMessage) {
        for (id, e) in &self.egress {
            if *id == origin {
                continue;
            }
            e.send(update);
        }
    }

    pub fn send_all(&self, update: &UpdateMessage) {
        for e in self.egress.values() {
            e.send(update);
        }
    }

    pub fn add_egress(&mut self, peer: IpAddr, egress: Egress<Cnx>) {
        self.egress.insert(peer, egress);
    }

    pub fn remove_egress(&mut self, peer: IpAddr) {
        self.egress.remove(&peer);
    }

    pub fn add_rule(&mut self, peer: IpAddr, rule: Rule4) -> Result<(), Error> {
        self.egress
            .get_mut(&peer)
            .ok_or(Error::UnknownPeer)?
            .rules
            .push(rule);
        Ok(())
    }
}

impl<Cnx: BgpConnection> Egress<Cnx> {
    fn send(&self, update: &UpdateMessage) {
        let mut permitted = UpdateMessage {
            path_attributes: update.path_attributes.clone(),
            ..Default::default()
        };

        for prefix in &update.withdrawn {
            if self.match_prefix(prefix) {
                permitted.withdrawn.push(prefix.clone());
            }
        }
        for prefix in &update.nlri {
            if self.match_prefix(prefix) {
                permitted.nlri.push(prefix.clone());
            }
        }

        if !permitted.withdrawn.is_empty() || !permitted.nlri.is_empty() {
            self.event_tx.send(FsmEvent::Announce(permitted)).unwrap();
        }
    }

    fn match_prefix(&self, prefix: &Prefix) -> bool {
        let mut allow = 0u16;
        let mut deny = 0u16;
        for rule in &self.rules {
            Self::match_rule(prefix.into(), rule, &mut allow, &mut deny);
        }
        allow > 0 && allow > deny
    }

    fn match_rule(
        prefix: Prefix4,
        rule: &Rule4,
        allow: &mut u16,
        deny: &mut u16,
    ) {
        if rule.matches(prefix) {
            match rule.policy.action {
                PolicyAction::Allow => {
                    *allow = u16::max(rule.policy.priority, *allow);
                }
                PolicyAction::Deny => {
                    *deny = u16::max(rule.policy.priority, *deny);
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rule_match_4() {
        let rule = Rule4 {
            prefix: Prefix4 {
                value: "1.2.0.0".parse().unwrap(),
                length: 16,
            },
            policy: Policy {
                action: PolicyAction::Allow,
                priority: 47,
            },
        };

        let prefix = Prefix4 {
            value: "1.2.0.0".parse().unwrap(),
            length: 16,
        };
        assert!(rule.matches(prefix));

        let prefix = Prefix4 {
            value: "1.2.3.0".parse().unwrap(),
            length: 24,
        };
        assert!(rule.matches(prefix));

        let prefix = Prefix4 {
            value: "1.0.0.0".parse().unwrap(),
            length: 8,
        };
        assert!(!rule.matches(prefix));

        let rule = Rule4 {
            prefix: Prefix4 {
                value: "0.0.0.0".parse().unwrap(),
                length: 0,
            },
            policy: Policy {
                action: PolicyAction::Allow,
                priority: 47,
            },
        };

        let prefix = Prefix4 {
            value: "9.37.17.222".parse().unwrap(),
            length: 24,
        };
        assert!(rule.matches(prefix));

        let prefix = Prefix4 {
            value: "0.0.0.0".parse().unwrap(),
            length: 0,
        };
        assert!(rule.matches(prefix));
    }
}
