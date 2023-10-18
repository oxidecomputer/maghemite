pub mod cli;

#[macro_export]
macro_rules! lock {
    ($mtx:expr) => {
        $mtx.lock().expect("lock mutex")
    };
}

#[macro_export]
macro_rules! read_lock {
    ($rwl:expr) => {
        $rwl.read().expect("rwlock read")
    };
}

#[macro_export]
macro_rules! write_lock {
    ($rwl:expr) => {
        $rwl.write().expect("rwlock write")
    };
}
