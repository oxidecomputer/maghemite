#[derive(Default)]
pub struct BgpState {
    pub in_rib: Rib,
    pub local_rib: Rib,
    pub out_rib: Rib,
}

#[derive(Default)]
pub struct Rib {
    //TODO
}
