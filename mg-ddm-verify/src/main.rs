// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Destination {
    addr: Ipv6Addr,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Prefix {
    destination: Destination,
    path: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Sled {
    name: String,
    ip: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let sleds: Vec<Sled> =
        serde_json::from_str(&std::fs::read_to_string("sleds.json")?)?;

    let all_sleds: Vec<String> = sleds.iter().map(|x| x.name.clone()).collect();
    let sled_to_ip: HashMap<String, String> = sleds
        .iter()
        .map(|x| (x.name.clone(), x.ip.clone()))
        .collect();

    let mut sled_prefixes = HashMap::<String, Vec<Prefix>>::new();
    let mut sled_originated = HashMap::<String, Vec<Destination>>::new();

    for sled in &all_sleds {
        let response: HashMap<String, Vec<Prefix>> = serde_json::from_str(
            &reqwest::get(format!(
                "http://{}:8000/prefixes",
                &sled_to_ip[sled]
            ))
            .await?
            .text()
            .await?,
        )?;

        // expect only one next hop, I'm querying sleds that only have one
        // connected interface (the other is an unconnected etherstub)
        assert_eq!(response.keys().len(), 1);
        let next_hop = response.keys().next().unwrap();

        sled_prefixes.insert(sled.clone(), response[next_hop].clone());

        let originated: Vec<Destination> = serde_json::from_str(
            &reqwest::get(format!(
                "http://{}:8000/originated",
                &sled_to_ip[sled]
            ))
            .await?
            .text()
            .await?,
        )?;

        sled_originated.insert(sled.clone(), originated);
    }

    // For each sled's advertised prefixes, check that they reached every sled.
    // A direction is "missed" if an advertised prefix isn't received by a sled.
    let mut missed_direction: HashMap<String, HashSet<String>> =
        HashMap::default();

    for sled in &all_sleds {
        let advertised_prefixes = &sled_originated[&sled.to_string()];

        // sleds will not see prefixes they advertised
        for other_sled in all_sleds.iter().filter(|x| *x != sled) {
            let other_sled_prefixes = &sled_prefixes[&other_sled.to_string()];

            for prefix in advertised_prefixes {
                if !other_sled_prefixes.iter().any(|x| x.destination == *prefix)
                {
                    eprintln!(
                        "sled {} advertised {:?} but {} didn't receive it!",
                        sled, prefix, other_sled,
                    );
                    missed_direction
                        .entry(sled.to_string())
                        .or_default()
                        .insert(other_sled.to_string());
                }
            }
        }
    }

    // show all missed directions
    println!("missed directions:");
    for (source, dests) in &missed_direction {
        for dest in dests {
            println!(" {} -> {}", source, dest);
        }
    }

    Ok(())
}
