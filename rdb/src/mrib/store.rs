// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Persistent storage of static multicast routes in sled.

use std::collections::BTreeMap;

use chrono::Utc;
use sled::Tree;
use slog::Logger;

use crate::db::UNIT_PERSISTENT;
use crate::error::Error;
use crate::log::rdb_log;
use crate::types::{MulticastRoute, MulticastRouteKey};

/// Name of the sled tree for persisted static multicast routes.
const STATIC_MCAST_ROUTES: &str = "static_mcast_routes";

/// The [`MulticastRoute`] version stored as the value in the
/// [`STATIC_MCAST_ROUTES`] tree.
///
/// Pinning the type follows [omicron's ledger versioning]. If the current API
/// moves to a different route type, reads and writes require conversions.
///
/// A new persisted version must retain a decode path for existing values.
///
/// [omicron's ledger versioning]: https://github.com/oxidecomputer/omicron/blob/cbb10ff6c3bae0ec445b0eca16d466a70cf6fc9a/sled-agent/config-reconciler/src/ledger/ledgered_config_versioning.rs#L30-L39
type PersistedMcastRoute = mg_api_types_versions::v14::mrib::MulticastRoute;

/// The [`MulticastRouteKey`] version serialized as the key in the
/// [`STATIC_MCAST_ROUTES`] tree. It is pinned for the same reason
/// documented in [`PersistedMcastRoute`].
///
/// Changing the serialized key format also requires migrating stored keys.
type PersistedMcastRouteKey =
    mg_api_types_versions::v14::mrib::MulticastRouteKey;

/// Encode `key` as its pinned JSON form.
fn encode_key(key: &MulticastRouteKey) -> Result<Vec<u8>, Error> {
    Ok(serde_json::to_vec::<PersistedMcastRouteKey>(key)?)
}

/// Decode a tree key, revalidating it through the pinned type's
/// deserializer.
fn decode_key(bytes: &[u8]) -> Result<MulticastRouteKey, Error> {
    Ok(serde_json::from_slice::<PersistedMcastRouteKey>(bytes)?)
}

/// Decode a stored route and check its key against the tree key.
fn decode_route(
    key: &MulticastRouteKey,
    value: &[u8],
) -> Result<PersistedMcastRoute, Error> {
    let route: PersistedMcastRoute = serde_json::from_slice(value)?;
    if route.key != *key {
        return Err(Error::DbValue(format!(
            "static multicast route value key {} does not match \
             tree key {key}",
            route.key
        )));
    }
    Ok(route)
}

/// Persistent store of static multicast routes.
pub(crate) struct StaticMcastStore {
    tree: Tree,
    log: Logger,
}

impl StaticMcastStore {
    /// Open the static multicast route tree in `db`.
    pub(crate) fn open(db: &sled::Db, log: Logger) -> Result<Self, Error> {
        Ok(Self {
            tree: db.open_tree(STATIC_MCAST_ROUTES)?,
            log,
        })
    }

    #[cfg(test)]
    pub(crate) fn tree(&self) -> &Tree {
        &self.tree
    }

    fn get(
        &self,
        key: &MulticastRouteKey,
    ) -> Result<Option<MulticastRoute>, Error> {
        Ok(self.tree.get(encode_key(key)?)?.and_then(|v| {
            decode_route(key, &v)
                .inspect_err(|e| {
                    rdb_log!(
                        self,
                        error,
                        "undecodable persisted static multicast route {}, \
                         resetting timestamps: {e}",
                        key;
                        "unit" => UNIT_PERSISTENT
                    );
                })
                .ok()
        }))
    }

    /// Persist `routes`.
    ///
    /// If a key appears more than once, the last route wins.
    ///
    /// A route already on disk keeps its `created` time. Its `updated` time
    /// moves to now only if something other than the timestamps changed. If
    /// the stored entry cannot be decoded, the new route's timestamps are
    /// used.
    ///
    /// The write consists of a sled transaction followed by a flush.
    ///
    /// Returns the routes as written.
    pub(crate) fn upsert(
        &self,
        routes: &[MulticastRoute],
    ) -> Result<Vec<MulticastRoute>, Error> {
        let normalized: Vec<MulticastRoute> = routes
            .iter()
            .map(|route| (route.key, route))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .map(|route| {
                let Some(prev) = self.get(&route.key)? else {
                    return Ok(route.clone());
                };
                let updated = if prev.eq_ignore_timestamps(route) {
                    prev.updated
                } else {
                    Utc::now()
                };
                Ok(MulticastRoute {
                    created: prev.created,
                    updated,
                    ..*route
                })
            })
            .collect::<Result<_, Error>>()?;

        let entries: Vec<(Vec<u8>, String)> = normalized
            .iter()
            .map(|route| {
                let value =
                    serde_json::to_string::<PersistedMcastRoute>(route)?;
                Ok((encode_key(&route.key)?, value))
            })
            .collect::<Result<_, Error>>()?;

        self.tree.transaction(|tx_db| {
            for (key, value) in &entries {
                tx_db.insert(key.as_slice(), value.as_str())?;
            }
            Ok(())
        })?;

        self.tree.flush()?;
        Ok(normalized)
    }

    /// Remove `keys` from persistence in one sled transaction, and then flush.
    pub(crate) fn remove(
        &self,
        keys: &[MulticastRouteKey],
    ) -> Result<(), Error> {
        let key_bytes: Vec<Vec<u8>> =
            keys.iter().map(encode_key).collect::<Result<_, Error>>()?;

        self.tree.transaction(|tx_db| {
            for kb in &key_bytes {
                tx_db.remove(kb.as_slice())?;
            }
            Ok(())
        })?;

        self.tree.flush()?;
        Ok(())
    }

    /// List valid static multicast routes from persistence.
    ///
    /// Malformed keys and values, including any key mismatches, are logged and
    /// skipped. Sled iteration errors are returned.
    pub(crate) fn list(&self) -> Result<Vec<MulticastRoute>, Error> {
        let decode = |(key, value): (sled::IVec, sled::IVec)| {
            let key = decode_key(&key)?;
            decode_route(&key, &value)
        };

        self.tree
            .iter()
            .map(|res| {
                let entry = res?;
                Ok(decode(entry)
                    .inspect_err(|e| {
                        rdb_log!(
                            self,
                            error,
                            "skipping undecodable static multicast route: {e}";
                            "unit" => UNIT_PERSISTENT
                        );
                    })
                    .ok())
            })
            .filter_map(Result::transpose)
            .collect()
    }
}
