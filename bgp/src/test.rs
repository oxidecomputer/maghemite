use crate::connection::test::{BgpConnectionChannel, BgpListenerChannel};
use crate::router::Router;
use std::thread::spawn;

#[test]
fn test_bgp_basics() {

    let r = Router::<BgpConnectionChannel>::new("0.0.0.0:179".into());
    spawn(move || {
        r.run::<BgpListenerChannel>();
    });

}
