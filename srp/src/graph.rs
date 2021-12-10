use std::collections::{HashMap, BTreeSet};
use std::cmp::{Eq, Ord};
use std::hash::Hash;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;

#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct Graph<Key: Eq + Hash> {
    // a -> b @ cost
    pub adj: HashMap<Key, HashMap<Key, u64>>,
}

impl<Key: Eq + Hash + Ord + Clone> Graph<Key> {
    pub fn new() -> Self {
        Self{
            adj: HashMap::new()
        }
    }
    pub fn from_edge_list(edges: Vec<(Key, Key, u64)>) -> Graph<Key> {
        let mut g = Graph{ adj: HashMap::new() };
        for e in edges {
            g.two_way_insert(e.0, e.1, e.2);
        }
        g
    }

    pub fn one_way_insert(&mut self, a: Key, b: Key, weight: u64) {
        match self.adj.get_mut(&a) {
            Some(l) => {
                l.insert(b, weight);
            }
            None => {
                let mut m = HashMap::new();
                m.insert(b, weight);
                self.adj.insert(a, m);
            }
        }
    }

    pub fn two_way_insert(&mut self, a: Key, b: Key, weight: u64) {
        self.one_way_insert(a.clone(), b.clone(), weight);
        self.one_way_insert(b.clone(), a.clone(), weight);
    }

    pub fn set_edge_weight(&mut self, a: Key, b: Key, weight: u64) {
        self.two_way_insert(a, b, weight);
    }

}

#[derive(Eq, Copy, Clone, Debug)]
struct WeightedVertex<Key: Eq + Hash> {
    id: Key,
    weight: u64,
}

impl<Key: Eq + Hash> WeightedVertex<Key> {
    fn new(id: Key, weight: u64) -> Self { WeightedVertex{id, weight} }
}

impl<Key: Eq + Hash> std::cmp::PartialEq for WeightedVertex<Key> {
    fn eq(&self, other: &Self) -> bool { self.id == other.id }
}

impl<Key: Eq + Hash + Ord> std::cmp::PartialOrd for WeightedVertex<Key> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<Key: Eq + Hash + Ord> std::cmp::Ord for WeightedVertex<Key> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.weight == other.weight {
            self.id.cmp(&other.id)
        } else {
            self.weight.cmp(&other.weight)
        }
    }
}

// bog standard Dijkstra's algorithm
//
// TODOs:
// .   Under the right conditions, since this is just a bog standard Dijkstra's
// .   algorithm, we may calculate paths through server routers, e.g. a server
// .   is providing transit. We don't want that. But the question is do we have
// .   some sort of hard coded logic in the algorithm itlsef to prevent that...
// .   or should this be the responsiblity of the elements computing the link
// .   weights to ensure that this situation never happens?
pub fn shortest_path<Key: Eq + Hash + Ord + Clone>(g: &Graph::<Key>, a: Key, b: Key) -> Vec<Key> {
    let mut dist = HashMap::<Key, u64>::new();
    let mut prev = HashMap::<Key, Option<Key>>::new();
    let mut q = BTreeSet::<WeightedVertex::<Key>>::new();
    for (x, _) in &g.adj {
        prev.insert(x.clone(), None);
        if *x == a {
            dist.insert(x.clone(), 0);
            q.insert(WeightedVertex{id: x.clone(), weight: 0});
        } else {
            dist.insert(x.clone(), u32::MAX as u64);
            q.insert(WeightedVertex{id: x.clone(), weight: u32::MAX as u64});
        }
    }

    while !q.is_empty() {
        // grab the closest next hop from the queue
        // since we check that the q is not empty, we always get Some here so an
        // unwrap is OK
        let u = q.pop_first().unwrap();

        // iterate over neighbors
        for nbr in g.adj.get(&u.id).unwrap() {

            // skip over neighbors that are no longer in the queue
            if !q.contains(&WeightedVertex::new(nbr.0.clone(), u32::MAX as u64)) {
                continue;
            }
            
            // if the distance to the neighbor is less than any traveled path
            // update the distance to the neighbor and set the previous hop
            // to this neighbor
            let alt = &u.weight + nbr.1;
            if alt < *dist.get(&nbr.0).unwrap() {
                // update queue weight for the neighbor
                q.insert(WeightedVertex{id: nbr.0.clone(), weight: alt});
                // update distance for the neighbor
                dist.insert(nbr.0.clone(), alt);
                // set the previous hop from this node to be the neighbor
                prev.insert(nbr.0.clone(), Some(u.id.clone()));

                // if we've arrived at the target stop
                if *nbr.0 == b {
                    break;
                }
            }
        }
    }

    let mut result = vec![b.clone()];
    let mut x = b;
    loop {
        let u = prev.get(&x).unwrap();
        if u.is_none() {
            break
        }
        let y = u.clone().unwrap();
        result.push(y.clone());
        x = y;
    }
    result.reverse();
    result
}

#[cfg(test)]
mod test {
    #[test]
    fn r2_disjoint_h01_h11() {
        use crate::graph::*;

        let mut g = Graph::from_edge_list(vec![
            // rack 1
            (1,5, 1), (1,6, 10),
            (2,5, 1), (2,6, 1),
            (3,5, 1), (3,6, 1),
            (4,5, 1), (4,6, 1),

            // rack 2
            (7,11, 1), (7,12, 1),
            (8,11, 1), (8,12, 1),
            (9,11, 1), (9,12, 1),
            (10,11, 1), (10,12, 1),

            // inter-rack
            (5,11, 1), (5,12, 999),
            (6,11, 999), (6,12, 1),
        ]);

        let p1 = shortest_path(&g, 1, 7);
        assert_eq!(p1, vec![1, 5, 11, 7]);

        g.set_edge_weight(1, 5, 99);
        g.set_edge_weight(5, 11, 99);
        g.set_edge_weight(11, 7, 99);

        let p2 = shortest_path(&g, 1, 7);
        assert_eq!(p2, vec![1, 6, 12, 7]);

        println!("kerplop {:?}", p1);
        println!("kerplop {:?}", p2);

    }

}
