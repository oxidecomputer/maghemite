#[macro_export]
macro_rules! wait_for_eq {
    ($measure:expr, $expect:expr, $period:expr, $count:expr, $desc:expr) => {
        for i in 0..$count {
            let measured = $measure;
            let expected = $expect;
            if measured == expected {
                break;
            }
            if i == $count - 1 {
                anyhow::bail!(
                    "{}: expected {:?}, got {:?}",
                    $desc,
                    expected,
                    measured
                );
            }
            tokio::time::sleep(Duration::from_secs($period)).await;
        }
    };
    ($measure:expr, $expect:expr, $desc:expr) => {
        wait_for_eq!($measure, $expect, 1, 20, $desc);
    };
}
