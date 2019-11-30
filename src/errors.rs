use thiserror::{ Error };

#[derive(Error, Debug)]
pub enum ObjectStoreError {
    #[error("Invalid item type")]
    ItemTypeParseError,
    #[error("An unknown error occurred")]
    Unknown
}
