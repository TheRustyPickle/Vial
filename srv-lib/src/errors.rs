use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Both view count and expiration cannot be empty")]
    ViewAndExpireEmpty,
    #[error("Invalid expiration value. It must be in the future with max {0} day")]
    InvalidExpire(i64),
    #[error("Invalid view count. It must be between 1 and {0}")]
    InvalidViewCount(i32),
    #[error("Database error: {0}")]
    DatabaseError(String),
}
