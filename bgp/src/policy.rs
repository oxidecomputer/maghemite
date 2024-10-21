// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! This file contains the Maghemite BGP policy engine. Policies fall into the
//! following categories.
//!
//! - Outgoing open message shaping.
//! - Outgoing update message shaping.
//! - Incoming open message checking.
//! - Incoming update message checking.
//!
//! Outgoing message shaping provides an opportunity for policy scripts to
//! modify and filter outgoing open and update messages. Incomming message
//! checking provides an opportunity for policy scripts to ensure open and
//! update messages meet policy requirements and can prevent them from being
//! accepted. Generally speaking shaping an incomming message does not make
//! sense, with one notable exception: local preference. Check scripts may
//! modify the local preference of incoming update messages to influence how
//! the Maghemite bestpath algorithm selects routes for data plane
//! installation.
//!
//! Shape and check scripts have full access to the message they are operating
//! over, as well as information about the peer the message is being exchanged
//! with.
//!
//! Policy scripts are operator defined and written in Rhai.

use crate::messages::{
    CapabilityCode, Message, OpenMessage, Prefix, UpdateMessage,
};
use crate::rhai_integration::*;
use rhai::{
    Dynamic, Engine, EvalAltResult, FnPtr, NativeCallContext, ParseError,
    Scope, AST,
};
use slog::{debug, info, Logger};
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Copy)]
pub struct PeerInfo {
    pub asn: u32,
    pub address: IpAddr,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub direction: Direction,
    pub message: Message,
    pub peer: PeerInfo,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ShaperResult {
    Emit(Message),
    Drop,
}

// TODO this is too general, we really only need to perform differences on
// updates
impl ShaperResult {
    pub fn difference(&self, other: &ShaperResult) -> ShaperResult {
        match (self, other) {
            (ShaperResult::Drop, ShaperResult::Drop) => ShaperResult::Drop,
            (ShaperResult::Drop, b @ ShaperResult::Emit(_)) => b.clone(),
            (ShaperResult::Emit(a), ShaperResult::Drop) => {
                ShaperResult::Emit(Self::diff_emit_to_drop(a))
            }
            (ShaperResult::Emit(a), ShaperResult::Emit(b)) => {
                ShaperResult::Emit(Self::diff_emit_to_emit(a, b))
            }
        }
    }

    fn diff_emit_to_drop(b: &Message) -> Message {
        match b {
            Message::Open(m) => Self::diff_emit_to_drop_open(m).into(),
            Message::Update(m) => Self::diff_emit_to_drop_update(m).into(),
            m @ Message::Notification(_) => m.clone(),
            m @ Message::KeepAlive => m.clone(),
            m @ Message::RouteRefresh(_) => m.clone(),
        }
    }

    fn diff_emit_to_drop_open(b: &OpenMessage) -> OpenMessage {
        b.clone()
    }

    fn diff_emit_to_drop_update(b: &UpdateMessage) -> UpdateMessage {
        // if we were emitting before and dropping now, that means all nlris
        // need to be sent out as withdraws.
        let mut new = b.clone();
        new.withdrawn.clone_from(&new.nlri);
        new.nlri.clear();
        new
    }

    fn diff_emit_to_emit(a: &Message, b: &Message) -> Message {
        match (a, b) {
            (Message::Update(a), Message::Update(b)) => {
                Self::diff_emit_to_emit_update(a, b).into()
            }
            (Message::Open(_), m @ Message::Open(_)) => m.clone(),
            // See todo above on this entire impl. The programmable policy
            // framework is not yet accessible from omicron so this code is
            // not reachable.
            _ => todo!(),
        }
    }

    fn diff_emit_to_emit_update(
        a: &UpdateMessage,
        b: &UpdateMessage,
    ) -> UpdateMessage {
        // anything that was previously being announced that is no longer
        // being announced, must be withdrawn
        let previous: HashSet<crate::messages::Prefix> =
            a.nlri.iter().cloned().collect();

        let current: HashSet<crate::messages::Prefix> =
            b.nlri.iter().cloned().collect();

        let mut new = b.clone();
        new.withdrawn = previous.difference(&current).cloned().collect();

        new
    }
}

impl ShaperResult {
    pub fn unwrap(self) -> Message {
        match self {
            Self::Drop => panic!("unwrap dropped shaper result"),
            Self::Emit(message) => message,
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum CheckerResult {
    Accept,
    Drop,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Policy eval error: {0}")]
    RhaiEval(#[from] Box<EvalAltResult>),

    #[error("Rhai parser error: {0}")]
    RhaiParse(#[from] ParseError),

    #[error("Incorrect open signature: expected 3 arguments, found {0}")]
    BadOpenSignature(usize),

    #[error("Open function missing")]
    MissingOpenFunction,

    #[error("Incorrect update signature: expected 3 arguments, found {0}")]
    BadUpdateSignature(usize),

    #[error("Update function missing")]
    MissingUpdateFunction,
}

pub fn new_rhai_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_max_expr_depths(50, 50);

    engine
        .register_type_with_name::<CapabilityCode>("CapabilityCode")
        .register_static_module(
            "CapabilityCode",
            rhai::exported_module!(capability_code_module).into(),
        );

    engine
        .register_type_with_name::<CheckerResult>("CheckerResult")
        .register_static_module(
            "CheckerResult",
            rhai::exported_module!(checker_result_module).into(),
        );

    engine
        .register_type_with_name::<ShaperResult>("ShaperResult")
        .register_static_module(
            "ShaperResult",
            rhai::exported_module!(shaper_result_module).into(),
        );

    engine
        .register_type_with_name::<OpenMessage>("OpenMessage")
        .register_fn("has_capability", OpenMessage::rhai_has_capability)
        .register_fn("add_four_octet_as", OpenMessage::add_four_octet_as)
        .register_fn("emit", OpenMessage::emit);

    engine
        .register_type_with_name::<UpdateMessage>("UpdateMessage")
        .register_fn("has_community", UpdateMessage::rhai_has_community)
        .register_fn("add_community", UpdateMessage::rhai_add_community)
        .register_fn("emit", UpdateMessage::emit)
        .register_raw_fn(
            "prefix_filter",
            [
                std::any::TypeId::of::<UpdateMessage>(),
                std::any::TypeId::of::<FnPtr>(),
            ],
            |context: NativeCallContext, args: &mut [&'_ mut Dynamic]| {
                // get the passed in function
                let fp = args[1].take().cast::<FnPtr>();
                let mut msg = args[0].write_lock::<UpdateMessage>().unwrap();
                msg.prefix_filter(|p| {
                    fp.call_raw(&context, None, [Dynamic::from(p.clone())])
                        .unwrap()
                        .cast::<bool>()
                });
                Ok(())
            },
        );

    engine
        .register_type_with_name::<Prefix>("Prefix")
        .register_fn("within", Prefix::within_rhai);

    #[cfg(debug_assertions)]
    {
        println!("Functions registered:");
        engine
            .gen_fn_signatures(false)
            .into_iter()
            .for_each(|func| println!("{func}"));
        println!();
    }

    engine
}

fn set_engine_logger(
    engine: &mut Engine,
    log: Logger,
    component: &str,
    asn: u32,
) {
    //TODO have a log scraper ship these to somewhere the user can get at them
    let info_log =
        log.new(slog::o!("component" => component.to_string(), "asn" => asn));
    engine.on_print(move |s| {
        info!(info_log, "{}", s);
    });

    let debug_log =
        log.new(slog::o!("component" => component.to_string(), "asn" => asn));
    engine.on_debug(move |s, src, pos| {
        debug!(debug_log, "[{src:?}:{pos}] {}", s);
    });
}

fn new_rhai_scope(ctx: &PolicyContext) -> Scope {
    let mut scope = Scope::new();
    scope.push("direction", ctx.direction);
    scope.push("message", ctx.message.clone());
    scope.push("peer", ctx.peer);
    scope
}

pub fn check_incoming_open(
    m: OpenMessage,
    checker: &AST,
    asn: u32,
    address: IpAddr,
    log: Logger,
) -> Result<CheckerResult, Error> {
    let ctx = PolicyContext {
        direction: Direction::Incoming,
        message: m.clone().into(),
        peer: PeerInfo { asn, address },
    };

    let mut scope = new_rhai_scope(&ctx);
    let mut engine = new_rhai_engine();
    set_engine_logger(&mut engine, log, "checker", asn);

    Ok(engine.call_fn::<CheckerResult>(
        &mut scope,
        checker,
        "open",
        (m, asn, address),
    )?)
}

pub fn check_incoming_update(
    m: UpdateMessage,
    checker: &AST,
    asn: u32,
    address: IpAddr,
    log: Logger,
) -> Result<CheckerResult, Error> {
    let ctx = PolicyContext {
        direction: Direction::Incoming,
        message: m.clone().into(),
        peer: PeerInfo { asn, address },
    };

    let mut scope = new_rhai_scope(&ctx);
    let mut engine = new_rhai_engine();
    set_engine_logger(&mut engine, log, "checker", asn);

    Ok(engine.call_fn::<CheckerResult>(
        &mut scope,
        checker,
        "update",
        (m, asn, address),
    )?)
}

pub fn shape_outgoing_open(
    m: OpenMessage,
    shaper: &AST,
    asn: u32,
    address: IpAddr,
    log: Logger,
) -> Result<ShaperResult, Error> {
    let ctx = PolicyContext {
        direction: Direction::Incoming,
        message: m.clone().into(),
        peer: PeerInfo { asn, address },
    };

    let mut scope = new_rhai_scope(&ctx);
    let mut engine = new_rhai_engine();
    set_engine_logger(&mut engine, log, "checker", asn);

    Ok(engine.call_fn::<ShaperResult>(
        &mut scope,
        shaper,
        "open",
        (m.clone(), asn as i64, address),
    )?)
}

pub fn shape_outgoing_update(
    m: UpdateMessage,
    shaper: &AST,
    asn: u32,
    address: IpAddr,
    log: Logger,
) -> Result<ShaperResult, Error> {
    let ctx = PolicyContext {
        direction: Direction::Incoming,
        message: m.clone().into(),
        peer: PeerInfo { asn, address },
    };

    let mut scope = new_rhai_scope(&ctx);
    let mut engine = new_rhai_engine();
    set_engine_logger(&mut engine, log, "checker", asn);

    Ok(engine.call_fn::<ShaperResult>(
        &mut scope,
        shaper,
        "update",
        (m.clone(), asn as i64, address),
    )?)
}

pub fn load_shaper(program_source: &str) -> Result<AST, Error> {
    // same as checker for now
    load_checker(program_source)
}

pub fn load_checker(program_source: &str) -> Result<AST, Error> {
    let engine = new_rhai_engine();
    let mut ast = engine.compile(program_source)?;
    ast.set_source(program_source);

    match ast.iter_functions().find(|f| f.name == "open") {
        Some(open) => {
            if open.params.len() != 3 {
                return Err(Error::BadOpenSignature(open.params.len()));
            }
        }
        None => return Err(Error::MissingOpenFunction),
    }

    match ast.iter_functions().find(|f| f.name == "update") {
        Some(update) => {
            if update.params.len() != 3 {
                return Err(Error::BadUpdateSignature(update.params.len()));
            }
        }
        None => return Err(Error::MissingUpdateFunction),
    }

    Ok(ast)
}

#[cfg(test)]
mod test {
    use crate::messages::{
        Community, PathAttribute, PathAttributeType, PathAttributeTypeCode,
        PathAttributeValue,
    };

    use super::*;
    use mg_common::log::init_logger;

    #[test]
    fn open_require_4byte_as() {
        // check that open messages without the 4-octet AS capability code get dropped
        let asn = 47;
        let addr = "198.51.100.1".parse().unwrap();
        let m = OpenMessage::new2(asn, 30, 1701);
        let source =
            std::fs::read_to_string("../bgp/policy/policy-check0.rhai")
                .unwrap();
        let ast = load_checker(&source).unwrap();
        let result =
            check_incoming_open(m, &ast, asn.into(), addr, init_logger())
                .unwrap();
        assert_eq!(result, CheckerResult::Drop);

        // check that open messages with the 4-octet AS capability code get accepted
        let m = OpenMessage::new4(asn.into(), 30, 1701);
        let result =
            check_incoming_open(m, &ast, asn.into(), addr, init_logger())
                .unwrap();
        assert_eq!(result, CheckerResult::Accept);
    }

    #[test]
    fn update_drop_on_no_export() {
        // check that messages with the no-export community are dropped
        let asn = 47;
        let addr = "198.51.100.1".parse().unwrap();
        let mut m = UpdateMessage::default();
        m.path_attributes.push(PathAttribute {
            typ: PathAttributeType {
                flags: 0,
                type_code: PathAttributeTypeCode::Communities,
            },
            value: PathAttributeValue::Communities(vec![Community::NoExport]),
        });
        let source =
            std::fs::read_to_string("../bgp/policy/policy-check0.rhai")
                .unwrap();
        let ast = load_checker(&source).unwrap();
        let result =
            check_incoming_update(m, &ast, asn, addr, init_logger()).unwrap();
        assert_eq!(result, CheckerResult::Drop);

        // check that messages without the no-export community are accepted
        let m = UpdateMessage::default();
        let result =
            check_incoming_update(m, &ast, asn, addr, init_logger()).unwrap();
        assert_eq!(result, CheckerResult::Accept);
    }

    #[test]
    fn open_add_4byte_as() {
        // check that open messages without the 4-octet AS capability code get dropped
        let asn = 100;
        let addr = "198.51.100.1".parse().unwrap();
        let mut m = OpenMessage::new2(asn, 30, 1701);
        let source =
            std::fs::read_to_string("../bgp/policy/policy-shape0.rhai")
                .unwrap();
        let ast = load_shaper(&source).unwrap();
        let result = shape_outgoing_open(
            m.clone(),
            &ast,
            asn.into(),
            addr,
            init_logger(),
        )
        .unwrap();
        m.add_four_octet_as(74);
        assert_eq!(result, ShaperResult::Emit(m.into()));
    }

    #[test]
    fn update_shape_community() {
        // check that messages with the no-export community are dropped
        let asn = 100;
        let addr = "198.51.100.1".parse().unwrap();
        let mut m = UpdateMessage::default();
        m.path_attributes.push(PathAttribute {
            typ: PathAttributeType {
                flags: 0,
                type_code: PathAttributeTypeCode::Communities,
            },
            value: PathAttributeValue::Communities(vec![Community::NoExport]),
        });
        let source =
            std::fs::read_to_string("../bgp/policy/policy-shape0.rhai")
                .unwrap();
        let ast = load_shaper(&source).unwrap();
        let result =
            shape_outgoing_update(m.clone(), &ast, asn, addr, init_logger())
                .unwrap();
        m.add_community(Community::UserDefined(1701));
        assert_eq!(result, ShaperResult::Emit(m.into()));
    }

    #[test]
    fn shape_update_prefixes() {
        let addr = "198.51.100.1".parse().unwrap();
        let originated = UpdateMessage {
            nlri: vec![
                "10.10.0.0/16".parse().unwrap(),
                "10.128.0.0/16".parse().unwrap(),
            ],
            ..Default::default()
        };
        let filtered = UpdateMessage {
            nlri: vec!["10.128.0.0/16".parse().unwrap()],
            ..Default::default()
        };
        let source =
            std::fs::read_to_string("../bgp/policy/shape-prefix0.rhai")
                .unwrap();
        let ast = load_shaper(&source).unwrap();

        // ASN 100 should not have any changes
        let result: UpdateMessage = shape_outgoing_update(
            originated.clone(),
            &ast,
            100,
            addr,
            init_logger(),
        )
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();

        assert_eq!(result, originated.clone());

        // ASN 65402 should have only the 10.128./16 prefix
        let result: UpdateMessage =
            shape_outgoing_update(originated, &ast, 65402, addr, init_logger())
                .unwrap()
                .unwrap()
                .try_into()
                .unwrap();

        assert_eq!(result, filtered);
    }
}
