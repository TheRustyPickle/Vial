use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Both view count and expiration cannot be empty")]
    ViewAndExpireEmpty,
    #[error("Invalid expiration value. It must be in the future with max 30 day")]
    InvalidExpire,
    #[error("Invalid view count. It must be between 1 and 1000")]
    InvalidViewCount,
    #[error("Database error: {0}")]
    DatabaseError(String),
}
