#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("datastore error {0}")]
    DataStore(#[from] sled::Error),

    #[error("serialization error {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("db key error{0}")]
    DbKey(String),
}
