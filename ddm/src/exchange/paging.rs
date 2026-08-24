// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Splitting a multicast exchange set so that it fits the paged V4 body limit.
//!
//! The underlay and tunnel sections of an exchange are bounded by the fabric's
//! prefix and tunnel endpoint counts. The multicast section is not: it grows
//! with the product of groups, VNIs, sources, and path length. Both directions
//! of the exchange therefore need a way to carry that set in more than one
//! HTTP body.
//!
//! A push splits with [`batch_multicast`], whose batches may be sent in any
//! order. Nothing else depends on where the boundaries fall, because
//! announcements and withdrawals within one update are already disjoint by
//! design.
//!
//! A pull uses keyset pagination with [`page_multicast`], where the boundaries
//! are not free. The reader synthesizes a withdrawal for every route it
//! imported from a peer that the peer's snapshot did not announce, so a group
//! that goes unread reads as withdrawn and drains that group's replication
//! members.
//!
//! Therefore, paging is ordered by group identity rather than by position, and
//! a [`MulticastPageSelector`] names the last group read. Per [Dropshot
//! pagination], a reader that scans a collection to the end sees every item
//! that existed both before and after the scan and was not renamed during it.
//! That is not true of a scheme whose cursor is a numeric offset. An insertion
//! ahead of an offset cursor shifts a later group backwards past it, and the
//! reader would treat the group it never saw as withdrawn.
//!
//! A keyset walk still races with concurrent change(s), but both outcomes are
//! harmless. A group added at a key the keyset walk has already passed is
//! missed until the next keyset walk. A group removed at a key the keyset walk
//! has not yet reached is correctly absent. Neither invents a withdrawal for a
//! group the peer still holds.
//!
//! [Dropshot pagination]: https://github.com/oxidecomputer/dropshot/blob/4ff9cb3f7fb29e477190dfccb100e244ed8562cf/dropshot/src/pagination.rs

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::ops::Bound;

use ddm_protocol::v3;
use ddm_protocol::v4::{
    MulticastOrigin, MulticastPathVector, MulticastUpdate, PullResponse, Update,
};
use dropshot::{EmptyScanParams, ResultsPage};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ExchangeError;

/// Bound on a paging-capable V4 exchange request or response.
///
/// It is a per-request memory guard rather than a multicast capacity limit: an
/// exchange set too large for one body is split across several requests, so the
/// limit constrains how much arrives at once, not how many groups the protocol
/// can carry. Legacy unpaged pulls keep their prior behavior and are not
/// subject to this client-side response bound.
pub(crate) const MAX_EXCHANGE_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Maximum encoded length of a Dropshot page token.
///
/// This reserves room for a continuation token while sizing a response, and
/// bounds a token read back off the wire. Dropshot's own `MAX_TOKEN_LENGTH` is
/// private, so the value is mirrored here rather than imported.
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 512;

/// Validate a Dropshot page token before placing it in a request URI.
///
/// Dropshot emits URL-safe base64 with optional padding. Pull responses are
/// peer input, so the client must not trust an arbitrary string to remain a
/// valid URI component.
pub(crate) fn page_token_query(token: &str) -> Result<String, ExchangeError> {
    if token.is_empty()
        || token.len() > MAX_PAGE_TOKEN_BYTES
        || !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '='))
    {
        return Err(ExchangeError::PageToken(String::from(
            "peer returned an invalid page token",
        )));
    }

    Ok(format!("page_token={token}"))
}

/// Multicast entries grouped under the identity that paging orders by.
pub(crate) type GroupedVectors =
    BTreeMap<MulticastOrigin, Vec<MulticastPathVector>>;

/// The sortable identity used by the multicast page token.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub(crate) struct MulticastOriginKey {
    pub overlay_group: IpAddr,
    pub underlay_group: Ipv6Addr,
    pub vni: u32,
    pub source: Option<IpAddr>,
}

impl From<&MulticastOrigin> for MulticastOriginKey {
    fn from(origin: &MulticastOrigin) -> Self {
        Self {
            overlay_group: origin.overlay_group,
            underlay_group: origin.underlay_group,
            vni: origin.vni,
            source: origin.source,
        }
    }
}

impl From<MulticastOriginKey> for MulticastOrigin {
    fn from(key: MulticastOriginKey) -> Self {
        Self {
            overlay_group: key.overlay_group,
            underlay_group: key.underlay_group,
            vni: key.vni,
            metric: 0,
            source: key.source,
        }
    }
}

/// Dropshot-compatible selector for multicast keyset pagination.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Serialize, Deserialize)]
pub(crate) struct MulticastPageSelector {
    pub last_seen: MulticastOriginKey,
}

impl MulticastPageSelector {
    pub(crate) fn after(&self) -> MulticastOrigin {
        self.last_seen.clone().into()
    }
}

/// Serialized length a value contributes to a set, including the separator
/// that follows it. Charging the separator to every element keeps a batch
/// within budget once its elements are joined into an array.
fn element_len<T: serde::Serialize>(value: &T) -> Result<usize, ExchangeError> {
    Ok(serde_json::to_string(value)?.len() + 1)
}

/// Measure the fixed portion of an update with an empty multicast section.
///
/// The section is present rather than absent, since an absent one serializes
/// as `null` and would leave the object's own braces uncharged.
fn update_envelope_len() -> Result<usize, ExchangeError> {
    Ok(serde_json::to_string(&Update::from(MulticastUpdate::default()))?.len())
}

/// Measure the fixed portion of a pull response with an empty multicast page.
///
/// The caller supplies the underlay and tunnel sections because they are
/// present only on the first page. The multicast array is included even when
/// empty so the returned length remains valid when that page contains entries.
pub(crate) fn response_envelope_len(
    underlay: Option<&HashSet<v3::PathVector>>,
    tunnel: Option<&HashSet<v3::TunnelOrigin>>,
) -> Result<usize, ExchangeError> {
    Ok(serde_json::to_string(&PullResponse {
        underlay: underlay.cloned(),
        tunnel: tunnel.cloned(),
        multicast: Some(HashSet::new()),
        next_page_token: None,
    })?
    .len())
}

/// Split a multicast exchange set into batches that each serialize within the
/// `limit`.
///
/// Batches are sized by measured serialized length rather than entry count,
/// because a path vector grows with the length of its path and an entry count
/// would either waste headroom or overshoot the limit.
///
/// An empty input yields a single empty batch, preserving the send that
/// callers already make for an empty set.
///
/// # Errors
///
/// Returns [`ExchangeError::MulticastVectorTooLarge`] when one vector exceeds
/// the budget on its own, since no split can make it sendable.
pub(crate) fn batch_multicast(
    groups: HashSet<MulticastPathVector>,
    limit: usize,
) -> Result<Vec<HashSet<MulticastPathVector>>, ExchangeError> {
    if groups.is_empty() {
        return Ok(vec![HashSet::new()]);
    }

    let budget = limit.saturating_sub(update_envelope_len()?);

    let mut batches = Vec::new();
    let mut batch = HashSet::new();
    let mut used = 0usize;

    for group in groups {
        let size = element_len(&group)?;
        if size > budget {
            return Err(ExchangeError::MulticastVectorTooLarge {
                group: group.origin.overlay_group,
                size,
                limit: budget,
            });
        }
        if used + size > budget {
            batches.push(std::mem::take(&mut batch));
            used = 0;
        }
        used += size;
        batch.insert(group);
    }

    if !batch.is_empty() {
        batches.push(batch);
    }

    Ok(batches)
}

/// Take the page of `groups` that follows `after`, and a selector for the next
/// page if any groups remain.
///
/// A page breaks only between groups, never inside one. Reconciliation is
/// keyed on the group, so a group split across two pages would read as a
/// partial announcement on the first of them.
///
/// # Errors
///
/// Returns [`ExchangeError::MulticastVectorTooLarge`] when one group's
/// vectors exceed the budget together, since no page boundary can make that
/// group servable.
pub(crate) fn page_multicast(
    groups: &GroupedVectors,
    after: Option<&MulticastOrigin>,
    limit: usize,
    response_envelope: usize,
) -> Result<
    (HashSet<MulticastPathVector>, Option<MulticastPageSelector>),
    ExchangeError,
> {
    let budget = limit
        .saturating_sub(response_envelope.saturating_add(MAX_PAGE_TOKEN_BYTES));

    let remaining = match after {
        Some(origin) => {
            groups.range((Bound::Excluded(origin), Bound::Unbounded))
        }
        None => groups.range(..),
    };

    let mut page = HashSet::new();
    let mut used = 0usize;
    let mut last = None;
    let mut truncated = false;

    for (origin, vectors) in remaining {
        let size = vectors
            .iter()
            .map(element_len)
            .sum::<Result<usize, ExchangeError>>()?;
        if size > budget {
            return Err(ExchangeError::MulticastVectorTooLarge {
                group: origin.overlay_group,
                size,
                limit: budget,
            });
        }
        if used + size > budget {
            truncated = true;
            break;
        }
        used += size;
        page.extend(vectors.iter().cloned());
        last = Some(origin);
    }

    // A group that is too large to serve on its own is rejected above, so the
    // first group of a page always fits and `last` is set whenever pagination
    // breaks.
    let next = if truncated {
        last.map(|origin| MulticastPageSelector {
            last_seen: origin.into(),
        })
    } else {
        None
    };

    Ok((page, next))
}

/// Group multicast entries under the identity that [`page_multicast`] orders
/// by.
pub(crate) fn group_by_origin(
    vectors: impl IntoIterator<Item = MulticastPathVector>,
) -> GroupedVectors {
    let mut grouped = GroupedVectors::new();
    for vector in vectors {
        grouped
            .entry(vector.origin.clone())
            .or_default()
            .push(vector);
    }
    grouped
}

/// Render a Dropshot page token for the next multicast page.
///
/// `ResultsPage` is used only for its token encoder. The exchange response has
/// additional fields, so it cannot use `ResultsPage` as its wire shape.
pub(crate) fn encode_page_token(
    selector: &MulticastPageSelector,
) -> Result<String, ExchangeError> {
    let page = ResultsPage::new(
        vec![selector.clone()],
        &EmptyScanParams {},
        |selector, _| selector.clone(),
    )
    .map_err(|e| ExchangeError::PageToken(e.to_string()))?;

    page.next_page.ok_or_else(|| {
        ExchangeError::PageToken(String::from(
            "Dropshot did not create a token for a non-empty page",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ddm_protocol::v4::MulticastPathHop;

    fn origin(index: u16) -> MulticastOrigin {
        MulticastOrigin {
            overlay_group: IpAddr::V6(Ipv6Addr::new(
                0xff04,
                0,
                0,
                0,
                0,
                0,
                0,
                index + 1,
            )),
            underlay_group: Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 1, index + 1),
            vni: 100,
            metric: 0,
            source: None,
        }
    }

    fn vector(index: u16, hops: usize) -> MulticastPathVector {
        MulticastPathVector {
            origin: origin(index),
            path: (0..hops)
                .map(|hop| MulticastPathHop {
                    router_id: format!("router-{index}-{hop}"),
                    underlay_addr: Ipv6Addr::new(
                        0xfd00,
                        0,
                        0,
                        0,
                        0,
                        0,
                        index + 1,
                        hop as u16,
                    ),
                    downstream_subscriber_count: 0,
                })
                .collect(),
        }
    }

    fn response_envelope_len() -> usize {
        serde_json::to_string(&PullResponse {
            multicast: Some(HashSet::new()),
            ..Default::default()
        })
        .unwrap()
        .len()
    }

    fn body_len(
        page: &HashSet<MulticastPathVector>,
        next_page_token: Option<&str>,
    ) -> usize {
        body_len_with_sections(page, next_page_token, None, None)
    }

    fn body_len_with_sections(
        page: &HashSet<MulticastPathVector>,
        next_page_token: Option<&str>,
        underlay: Option<&HashSet<v3::PathVector>>,
        tunnel: Option<&HashSet<v3::TunnelOrigin>>,
    ) -> usize {
        serde_json::to_string(&PullResponse {
            underlay: underlay.cloned(),
            tunnel: tunnel.cloned(),
            multicast: Some(page.clone()),
            next_page_token: next_page_token.map(String::from),
        })
        .unwrap()
        .len()
    }

    /// Read every page of `groups`, as a peer would, and return what the
    /// keyset walk announced along with the number of pages it took.
    fn walk(
        groups: &GroupedVectors,
        limit: usize,
    ) -> (HashSet<MulticastPathVector>, usize) {
        let mut seen = HashSet::new();
        let mut selector: Option<MulticastPageSelector> = None;
        let mut pages = 0;

        loop {
            let after = selector.as_ref().map(MulticastPageSelector::after);
            let (page, next) = page_multicast(
                groups,
                after.as_ref(),
                limit,
                response_envelope_len(),
            )
            .unwrap();
            pages += 1;
            let next_token =
                next.as_ref().map(encode_page_token).transpose().unwrap();
            assert!(body_len(&page, next_token.as_deref()) <= limit);
            seen.extend(page);
            match next {
                Some(next) => selector = Some(next),
                None => return (seen, pages),
            }
        }
    }

    #[test]
    fn empty_exchange_set_yields_one_empty_batch() {
        let batches =
            batch_multicast(HashSet::new(), MAX_EXCHANGE_BODY_BYTES).unwrap();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].is_empty());
    }

    #[test]
    fn exchange_set_within_budget_stays_in_one_batch() {
        let groups: HashSet<_> = (0..8).map(|i| vector(i, 3)).collect();
        let batches =
            batch_multicast(groups.clone(), MAX_EXCHANGE_BODY_BYTES).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0], groups);
    }

    #[test]
    fn oversized_exchange_set_splits_and_preserves_every_vector() {
        let groups: HashSet<_> = (0..10).map(|i| vector(i, 3)).collect();
        let per = groups
            .iter()
            .map(|v| element_len(v).unwrap())
            .max()
            .unwrap();
        let limit = update_envelope_len().unwrap() + per * 3;

        let batches = batch_multicast(groups.clone(), limit).unwrap();
        assert!(batches.len() > 1);

        // Measure the update each batch actually serializes to, rather than
        // re-deriving the sizing the implementation used to build it.
        for batch in &batches {
            let body = serde_json::to_string(&Update::from(
                MulticastUpdate::announce(batch.clone()),
            ))
            .unwrap();
            assert!(body.len() <= limit, "batch body {} > {limit}", body.len());
        }

        let flattened: HashSet<_> = batches.into_iter().flatten().collect();
        assert_eq!(flattened, groups);
    }

    #[test]
    fn vector_larger_than_budget_is_an_error() {
        let group = vector(0, 3);
        let limit =
            update_envelope_len().unwrap() + element_len(&group).unwrap() - 1;

        let err = batch_multicast(HashSet::from([group.clone()]), limit)
            .expect_err("a vector exceeding the budget cannot be sent");
        assert!(matches!(
            err,
            ExchangeError::MulticastVectorTooLarge { group: g, .. }
                if g == group.origin.overlay_group
        ));
    }

    #[test]
    fn oversized_group_is_rejected_by_page_multicast() {
        let group = vector(0, 3);
        let groups = group_by_origin([group.clone()]);
        let limit = response_envelope_len()
            + MAX_PAGE_TOKEN_BYTES
            + element_len(&group).unwrap()
            - 1;

        let err = page_multicast(&groups, None, limit, response_envelope_len())
            .expect_err("a group exceeding the page budget cannot be served");
        assert!(matches!(
            err,
            ExchangeError::MulticastVectorTooLarge { group: g, .. }
                if g == group.origin.overlay_group
        ));
    }

    #[test]
    fn snapshot_within_budget_is_one_page() {
        let groups = group_by_origin((0..8).map(|i| vector(i, 3)));
        let (seen, pages) = walk(&groups, MAX_EXCHANGE_BODY_BYTES);
        assert_eq!(pages, 1);
        assert_eq!(seen.len(), 8);
    }

    #[test]
    fn page_budget_includes_unicast_sections_and_cursor() {
        let underlay = HashSet::from([v3::PathVector {
            destination: "2001:db8::/64".parse().unwrap(),
            path: vec![String::from("router")],
        }]);
        let tunnel = HashSet::from([v3::TunnelOrigin {
            overlay_prefix: "192.0.2.0/24".parse().unwrap(),
            boundary_addr: "2001:db8::1".parse().unwrap(),
            vni: 100,
            metric: 0,
        }]);
        let groups = group_by_origin((0..6).map(|i| vector(i, 3)));
        let per = groups
            .values()
            .flatten()
            .map(|v| element_len(v).unwrap())
            .max()
            .unwrap();
        let envelope =
            super::response_envelope_len(Some(&underlay), Some(&tunnel))
                .unwrap();
        let limit = envelope + MAX_PAGE_TOKEN_BYTES + per * 2;

        let (page, next) =
            page_multicast(&groups, None, limit, envelope).unwrap();
        let token = next.as_ref().map(encode_page_token).transpose().unwrap();

        assert!(next.is_some(), "the test set should require another page");
        assert!(
            body_len_with_sections(
                &page,
                token.as_deref(),
                Some(&underlay),
                Some(&tunnel),
            ) <= limit
        );
    }

    #[test]
    fn keyset_walk_reads_every_group_exactly_once() {
        let vectors: Vec<_> = (0..10).map(|i| vector(i, 3)).collect();
        let groups = group_by_origin(vectors.clone());
        let per = vectors
            .iter()
            .map(|v| element_len(v).unwrap())
            .max()
            .unwrap();
        let limit = response_envelope_len() + MAX_PAGE_TOKEN_BYTES + per * 3;

        let (seen, pages) = walk(&groups, limit);
        assert!(pages > 1);
        assert_eq!(seen, vectors.into_iter().collect::<HashSet<_>>());
    }

    /// A group with several path vectors is announced as a unit. Splitting it
    /// would read as a partial announcement, since reconciliation is keyed on
    /// the group rather than on the vector.
    #[test]
    fn a_group_is_never_split_across_pages() {
        let mut groups = GroupedVectors::new();
        for i in 0..6u16 {
            groups.insert(
                origin(i),
                (0..3).map(|hop| vector(i, hop + 1)).collect(),
            );
        }
        let limit = response_envelope_len()
            + MAX_PAGE_TOKEN_BYTES
            + groups
                .values()
                .map(|v| {
                    v.iter().map(|v| element_len(v).unwrap()).sum::<usize>()
                })
                .max()
                .unwrap()
                * 2;

        let mut selector: Option<MulticastPageSelector> = None;
        let mut pages = 0;
        loop {
            let after = selector.as_ref().map(MulticastPageSelector::after);
            let (page, next) = page_multicast(
                &groups,
                after.as_ref(),
                limit,
                response_envelope_len(),
            )
            .unwrap();
            pages += 1;
            for (origin, vectors) in &groups {
                let present =
                    vectors.iter().filter(|v| page.contains(*v)).count();
                assert!(
                    present == 0 || present == vectors.len(),
                    "group {} split: {present} of {} vectors",
                    origin.overlay_group,
                    vectors.len(),
                );
            }
            match next {
                Some(next) => selector = Some(next),
                None => break,
            }
        }
        assert!(pages > 1);
    }

    /// A group inserted beyond the cursor during a keyset walk is still read,
    /// and one removed beyond the cursor is correctly absent. Neither disturbs
    /// the groups the keyset walk already passed.
    #[test]
    fn change_beyond_the_cursor_is_picked_up_by_the_same_keyset_walk() {
        let mut groups = group_by_origin((0..6).map(|i| vector(i, 2)));
        let per = groups
            .values()
            .flatten()
            .map(|v| element_len(v).unwrap())
            .max()
            .unwrap();
        let limit = response_envelope_len() + MAX_PAGE_TOKEN_BYTES + per * 2;

        let (first, next) =
            page_multicast(&groups, None, limit, response_envelope_len())
                .unwrap();
        let selector = next.expect("six groups exceed a two-group page");

        // The last group sorts beyond any page boundary this keyset walk has
        // reached, so removing it now is a change the keyset walk has not
        // passed.
        let removed = groups.keys().next_back().unwrap().clone();
        groups.remove(&removed);

        let mut seen = first;
        let mut selector = Some(selector);
        while let Some(current) = selector {
            let after = current.after();
            let (page, next) = page_multicast(
                &groups,
                Some(&after),
                limit,
                response_envelope_len(),
            )
            .unwrap();
            seen.extend(page);
            selector = next;
        }

        assert!(!seen.iter().any(|v| v.origin == removed));
        assert_eq!(seen.len(), 5);
    }

    /// A group present for the whole keyset walk appears in some page even when
    /// groups are inserted ahead of the cursor, which is what keeps the
    /// reader from synthesizing a withdrawal for it.
    #[test]
    fn insertion_before_the_cursor_cannot_drop_a_present_group() {
        let stable: Vec<_> = (10..16u16).map(|i| vector(i, 2)).collect();
        let mut groups = group_by_origin(stable.clone());
        let per = stable
            .iter()
            .map(|v| element_len(v).unwrap())
            .max()
            .unwrap();
        let limit = response_envelope_len() + MAX_PAGE_TOKEN_BYTES + per * 2;

        let mut seen = HashSet::new();
        let mut selector: Option<MulticastPageSelector> = None;
        let mut inserted = 0u16;

        loop {
            let after = selector.as_ref().map(MulticastPageSelector::after);
            let (page, next) = page_multicast(
                &groups,
                after.as_ref(),
                limit,
                response_envelope_len(),
            )
            .unwrap();
            seen.extend(page);

            // Insert a group that sorts ahead of every stable group, so it
            // lands behind the cursor on each subsequent request.
            let early = vector(inserted, 2);
            groups.insert(early.origin.clone(), vec![early]);
            inserted += 1;

            match next {
                Some(next) => selector = Some(next),
                None => break,
            }
        }

        for vector in &stable {
            assert!(
                seen.contains(vector),
                "group {} was present throughout but went unread",
                vector.origin.overlay_group,
            );
        }
    }

    #[test]
    fn a_group_round_trips_through_its_token() {
        let mut source_specific = origin(3);
        source_specific.source = Some("192.0.2.7".parse().unwrap());
        let selector = MulticastPageSelector {
            last_seen: (&source_specific).into(),
        };
        let token = encode_page_token(&selector).unwrap();
        assert!(token.len() <= MAX_PAGE_TOKEN_BYTES);

        let params: dropshot::PaginationParams<
            EmptyScanParams,
            MulticastPageSelector,
        > = serde_json::from_value(serde_json::json!({
            "page_token": token,
        }))
        .unwrap();
        match params.page {
            dropshot::WhichPage::Next(decoded) => {
                assert_eq!(decoded, selector);
                assert_eq!(decoded.after(), source_specific);
            }
            dropshot::WhichPage::First(_) => {
                panic!("a page token must select the next page")
            }
        }

        let any_source = origin(3);
        let selector = MulticastPageSelector {
            last_seen: (&any_source).into(),
        };
        assert_eq!(selector.after(), any_source);
    }

    /// A token rides in a query value, so its URL-safe encoding needs no
    /// additional escaping. Dropshot retains base64 padding.
    #[test]
    fn a_token_is_query_safe() {
        let selector = MulticastPageSelector {
            last_seen: (&origin(3)).into(),
        };
        let token = encode_page_token(&selector).unwrap();
        assert!(
            token.chars().all(|c| {
                c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '='
            }),
            "token {token} would need escaping",
        );
    }

    #[test]
    fn invalid_page_tokens_are_rejected_before_uri_construction() {
        for token in ["", "not valid", "%", "a/b", &"a".repeat(513)] {
            assert!(
                page_token_query(token).is_err(),
                "token {token:?} should be rejected",
            );
        }

        assert_eq!(page_token_query("abc-_==").unwrap(), "page_token=abc-_==",);
    }
}
