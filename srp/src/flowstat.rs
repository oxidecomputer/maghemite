use rand_distr::{Distribution, Weibull};

pub struct PortStats {
    pub egress_rate: u64,
    pub ingresss_rate: u64,
}

impl PortStats {


    pub fn new() -> Self {

        let mut rng = rand::thread_rng();
        let dist = Weibull::new(1.0, 1.5).unwrap();

        // kick back a random weibull sample up to a few gigabits
        PortStats{
            egress_rate: (1e9 * dist.sample(&mut rng)) as u64,
            ingresss_rate: (1e9 * dist.sample(&mut rng)) as u64,
        }
    }
}