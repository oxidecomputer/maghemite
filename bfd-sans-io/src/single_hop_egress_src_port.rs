// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

const OFFSET_RANGE: u16 =
    (u16::MAX - SingleHopEgressSrcPort::SOURCE_PORT_BEGIN) + 1;

/// Helper for choosing a source port for egress sockets in single-hop BFD.
///
/// Per RFC 5881 §4, single hop BFD control packets MUST have a source port in
/// the range `[49152, 65535]`. We assume we'll never have more than 16384
/// active sessions, so do not support the RFD's note that source ports "MAY be
/// reused on multiple sessions".
///
/// This type is a concurrency-safe iterator over that range.
pub(crate) struct SingleHopEgressSrcPort {
    next_offset: AtomicU16,
}

impl SingleHopEgressSrcPort {
    pub(crate) const SOURCE_PORT_BEGIN: u16 = 49152;

    pub(crate) fn new() -> Self {
        Self {
            next_offset: AtomicU16::new(0),
        }
    }

    pub(crate) fn next(&self) -> u16 {
        let offset =
            self.next_offset.fetch_add(1, Ordering::Relaxed) % OFFSET_RANGE;
        Self::SOURCE_PORT_BEGIN + offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_strategy::proptest;

    #[test]
    fn initial_port_choices_are_from_start_of_range() {
        let expected = (SingleHopEgressSrcPort::SOURCE_PORT_BEGIN..)
            .take(10)
            .collect::<Vec<_>>();

        let src_port = SingleHopEgressSrcPort::new();
        let mut computed = Vec::new();
        for _ in 0..expected.len() {
            computed.push(src_port.next());
        }

        assert_eq!(expected, computed);
    }

    #[test]
    fn port_choices_wrap_around_at_end() {
        let close_to_end = 65530;

        let expected = (close_to_end..=u16::MAX)
            .chain(SingleHopEgressSrcPort::SOURCE_PORT_BEGIN..)
            .take(10)
            .collect::<Vec<_>>();

        let src_port = SingleHopEgressSrcPort::new();

        // Artificially bump the internal offset so we skip to the end.
        src_port.next_offset.fetch_add(
            close_to_end - SingleHopEgressSrcPort::SOURCE_PORT_BEGIN,
            Ordering::Relaxed,
        );

        let mut computed = Vec::new();
        for _ in 0..expected.len() {
            computed.push(src_port.next());
        }

        assert_eq!(expected, computed);
    }

    #[proptest]
    fn src_port_is_always_in_range(offset: u16) {
        let src_port = SingleHopEgressSrcPort::new();

        // Regardless of the inner offset, which we set arbitrarily here, we
        // should always get ports in the expected range.
        src_port.next_offset.store(offset, Ordering::Relaxed);

        let port = src_port.next();
        assert!(
            port >= SingleHopEgressSrcPort::SOURCE_PORT_BEGIN,
            "invalid port: {port}"
        );
    }
}
