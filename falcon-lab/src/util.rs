#[macro_export]
macro_rules! wait_for_eq {
    ($measure:expr, $expect:expr, $period:expr, $count:expr, $desc:expr) => {
        for i in 0..$count {
            let measured = $measure;
            let expected = $expect;
            if measured == expected {
                break;
            }
            client_common::println_nopipe!(
                "{}: iteration {}/{}: expected {:?}, got {:?}",
                $desc,
                i + 1,
                $count,
                expected,
                measured
            );
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

#[macro_export]
macro_rules! wait_for_eq_stable {
    ($measure:expr, $expect:expr, $stable_count:expr, $period:expr, $count:expr, $desc:expr) => {
        let stable_count: usize = $stable_count;
        let mut consecutive = 0usize;
        for i in 0..$count {
            let measured = $measure;
            let expected = $expect;
            if measured == expected {
                consecutive += 1;
                if consecutive >= stable_count {
                    break;
                }
                client_common::println_nopipe!(
                    "{}: iteration {}/{}: matched {:?} ({}/{} consecutive)",
                    $desc,
                    i + 1,
                    $count,
                    measured,
                    consecutive,
                    stable_count
                );
            } else {
                if consecutive == 0 {
                    client_common::println_nopipe!(
                        "{}: iteration {}/{}: expected {:?}, got {:?}",
                        $desc,
                        i + 1,
                        $count,
                        expected,
                        measured
                    );
                } else {
                    client_common::println_nopipe!(
                        "{}: iteration {}/{}: expected {:?}, got {:?} (reset after {}/{} consecutive)",
                        $desc,
                        i + 1,
                        $count,
                        expected,
                        measured,
                        consecutive,
                        stable_count
                    );
                }
                consecutive = 0;
            }
            if i == $count - 1 {
                anyhow::bail!(
                    "{}: expected {:?} for {} consecutive samples, got {:?} ({} consecutive)",
                    $desc,
                    expected,
                    stable_count,
                    measured,
                    consecutive
                );
            }
            tokio::time::sleep(Duration::from_secs($period)).await;
        }
    };
    ($measure:expr, $expect:expr, $stable_count:expr, $desc:expr) => {
        wait_for_eq_stable!($measure, $expect, $stable_count, 1, 20, $desc);
    };
}
