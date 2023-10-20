#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("dpd error {0}")]
    Dpd(#[from] dpd_client::Error<dpd_client::types::Error>),
}
