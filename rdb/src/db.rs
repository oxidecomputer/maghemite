//! The routing database (rdb).
//!
//! ## Structure
//!
//! The rdb is a key-value store for routing information. There are a
//! pre-defined set of keys for routing elements such as routes and and
//! nexthops. Each key may exist in multiple key spaces. For example in one
//! keyspace a route key may map to a nexthop, and in another the route key may
//! map to a set of BGP attributes.
//!
//! ### Key Spaces
//!
//! - nexthop:  `RouteKey`       -> `IpAddr`
//! - bgp:      `RouteKey`       -> `BgpAttributes`
//! - metrics:  `RouteMetricKey` -> `u64`
//! - bfd:      `IpAddr`         -> `Status`
//!

// TODO: break out key spaces into
// - inbound RIB
// - local RIB
// - outbound RIB

use crate::types::*;
use anyhow::Result;

#[derive(Clone)]
pub struct Db(sled::Db);
unsafe impl Sync for Db {}
unsafe impl Send for Db {}

impl Db {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self(sled::open(path)?))
    }

    pub fn get_nexthop4(&self, route_key: Route4Key) -> Result<bool> {
        let tree = self.0.open_tree("nexthop")?;

        let key = to_buf(&route_key)?;

        Ok(tree.get(key)?.is_some())
    }

    pub fn set_nexthop4(&self, route_key: Route4Key) -> Result<()> {
        let tree = self.0.open_tree("nexthop")?;

        let key = to_buf(&route_key)?;
        tree.insert(key, "")?;

        Ok(())
    }

    pub fn remove_nexthop4(&self, route_key: Route4Key) -> Result<()> {
        let tree = self.0.open_tree("nexthop")?;

        let key = to_buf(&route_key)?;
        tree.remove(key)?;

        Ok(())
    }
}
