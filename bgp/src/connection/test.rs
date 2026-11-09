// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![deny(
    clippy::wildcard_enum_match_arm,
    clippy::match_wildcard_for_single_variants
)]

use super::{
    ConnectError, ConnectErrorDiscriminants as Connect, ConnectionPolicyError,
    ConnectionPolicyErrorDiscriminants as Policy, ListenerAcceptError,
    ListenerAcceptErrorDiscriminants as Accept, ListenerBindError,
    ListenerBindErrorDiscriminants as Bind, Md5Error,
    Md5ErrorDiscriminants as Md5, SendError, SendErrorDiscriminants as Send,
    StartRecvLoopError, StartRecvLoopErrorDiscriminants as Recv,
};
use crate::error::Error;
use slog_error_chain::InlineErrorChain;
use std::io;
use strum::IntoEnumIterator;

// Register new connection error types here; generated discriminants and
// exhaustive matches cover their variants. This module is test-only.
#[derive(Debug, thiserror::Error, strum::EnumDiscriminants)]
#[error(transparent)]
#[strum_discriminants(derive(strum::EnumIter))]
enum BgpConnectionError {
    ListenerBind(#[from] ListenerBindError),
    ListenerAccept(#[from] ListenerAcceptError),
    Md5(#[from] Md5Error),
    Policy(#[from] ConnectionPolicyError),
    Connect(#[from] ConnectError),
    Send(#[from] SendError),
    StartRecvLoop(#[from] StartRecvLoopError),
}

fn io_error() -> io::Error {
    io::Error::other("I/O cause")
}

fn route_error() -> Md5Error {
    Md5Error::RouteQuery(
        anyhow::Error::new(io::Error::other("route unavailable"))
            .context("routing socket request failed"),
    )
}

const ROUTE_CHAIN: &str = "failed to query route to peer: routing socket request failed: route unavailable";

fn fixtures<K, E>(
    build: impl Fn(K) -> (E, &'static str),
) -> Vec<(BgpConnectionError, &'static str)>
where
    K: IntoEnumIterator + Copy + std::fmt::Debug + PartialEq,
    K: for<'a> From<&'a E>,
    E: Into<BgpConnectionError>,
{
    K::iter()
        .map(|kind| {
            let (error, expected) = build(kind);
            // Catch fixtures that accidentally construct another variant.
            assert_eq!(K::from(&error), kind);
            (error.into(), expected)
        })
        .collect()
}

impl BgpConnectionErrorDiscriminants {
    fn cases(self) -> Vec<(BgpConnectionError, &'static str)> {
        match self {
            Self::ListenerBind => fixtures(|kind| match kind {
                Bind::AddressResolution => (
                    ListenerBindError::AddressResolution(io_error()),
                    "failed to resolve listen address: I/O cause",
                ),
                Bind::NoAddress => (
                    ListenerBindError::NoAddress,
                    "listen address resolved to no addresses",
                ),
                Bind::ListenerSetup => (
                    ListenerBindError::ListenerSetup(io_error()),
                    "failed to initialize listener: I/O cause",
                ),
            }),
            Self::ListenerAccept => fixtures(|kind| match kind {
                Accept::Timeout => (
                    ListenerAcceptError::Timeout,
                    "timed out waiting for an inbound connection",
                ),
                Accept::UnknownPeer => (
                    ListenerAcceptError::UnknownPeer(
                        crate::session::PeerId::Ip(
                            "192.0.2.1".parse().unwrap(),
                        ),
                    ),
                    "connection attempt from unknown peer: 192.0.2.1",
                ),
                Accept::NewConnectionSetup => (
                    ListenerAcceptError::NewConnectionSetup(io_error()),
                    "failed to configure accepted connection: I/O cause",
                ),
                Accept::Listener => (
                    ListenerAcceptError::Listener(io_error()),
                    "failed to accept connection: I/O cause",
                ),
            }),
            Self::Md5 => fixtures(|kind| match kind {
                Md5::RouteQuery => (route_error(), ROUTE_CHAIN),
                Md5::LocalAddressQuery => (
                    Md5Error::LocalAddressQuery(
                        anyhow::Error::new(io_error())
                            .context("address enumeration failed"),
                    ),
                    "failed to query local IP addresses: address enumeration failed: I/O cause",
                ),
                Md5::NoMatchingSourceAddress => (
                    Md5Error::NoMatchingSourceAddress,
                    "no local source address available for MD5 authentication",
                ),
                Md5::AuthenticationSetup => (
                    Md5Error::AuthenticationSetup(io_error()),
                    "failed to set up MD5 authentication: I/O cause",
                ),
            }),
            Self::Policy => fixtures(|kind| match kind {
                Policy::MinTtl => (
                    ConnectionPolicyError::MinTtl(io_error()),
                    "failed to configure minimum TTL: I/O cause",
                ),
                Policy::Md5 => {
                    (ConnectionPolicyError::Md5(route_error()), ROUTE_CHAIN)
                }
            }),
            Self::Connect => fixtures(|kind| match kind {
                Connect::ConnectionSetup => (
                    ConnectError::ConnectionSetup(io_error()),
                    "failed to initialize outbound connection: I/O cause",
                ),
                Connect::Md5 => (ConnectError::Md5(route_error()), ROUTE_CHAIN),
                Connect::ThreadSpawn => (
                    ConnectError::ThreadSpawn(io_error()),
                    "failed to spawn connector thread: I/O cause",
                ),
            }),
            Self::Send => fixtures(|kind| match kind {
                Send::Encode => (
                    SendError::Encode(Box::new(Error::BadVersion(3))),
                    "failed to encode BGP message: bad version: 3",
                ),
                Send::TooLarge => (
                    SendError::TooLarge(65536),
                    "BGP message length 65536 exceeds the wire limit",
                ),
                Send::Write => (
                    SendError::Write(io_error()),
                    "failed to write BGP message: I/O cause",
                ),
            }),
            Self::StartRecvLoop => fixtures(|kind| match kind {
                Recv::AcquireReader => (
                    StartRecvLoopError::AcquireReader(io_error()),
                    "failed to acquire connection reader: I/O cause",
                ),
                Recv::ThreadSpawn => (
                    StartRecvLoopError::ThreadSpawn(io_error()),
                    "failed to spawn receive thread: I/O cause",
                ),
            }),
        }
    }
}

#[test]
fn connection_error_chains_include_each_cause_once() {
    for kind in BgpConnectionErrorDiscriminants::iter() {
        for (error, expected) in kind.cases() {
            assert_eq!(BgpConnectionErrorDiscriminants::from(&error), kind);
            assert_eq!(
                InlineErrorChain::new(&error).to_string(),
                expected,
                "{error:?}",
            );

            // Also exercise the wrappers actually used by session.rs.
            let wrapped = match error {
                BgpConnectionError::Send(e) => Error::from(e),
                BgpConnectionError::StartRecvLoop(e) => Error::from(e),
                BgpConnectionError::ListenerBind(_)
                | BgpConnectionError::ListenerAccept(_)
                | BgpConnectionError::Md5(_)
                | BgpConnectionError::Policy(_)
                | BgpConnectionError::Connect(_) => continue,
            };
            assert_eq!(
                InlineErrorChain::new(&wrapped).to_string(),
                expected,
                "{wrapped:?}",
            );
        }
    }
}
