// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use ddm_types::exchange::PathVector;
use oxnet::Ipv6Net;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
pub struct Sled {
    name: String,
    ip: String,
}

fn main() -> Result<()> {
    oxide_tokio_rt::run(run())
}

async fn run() -> Result<()> {
    let sleds: Vec<Sled> =
        serde_json::from_str(&std::fs::read_to_string("sleds.json")?)?;

    let all_sleds: Vec<String> = sleds.iter().map(|x| x.name.clone()).collect();
    let sled_to_ip: HashMap<String, String> = sleds
        .iter()
        .map(|x| (x.name.clone(), x.ip.clone()))
        .collect();

    let mut sled_prefixes = HashMap::<String, Vec<PathVector>>::new();
    let mut sled_originated = HashMap::<String, Vec<Ipv6Net>>::new();

    for sled in &all_sleds {
        let response: HashMap<String, Vec<PathVector>> = serde_json::from_str(
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

        let originated: Vec<Ipv6Net> = serde_json::from_str(
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
