use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct EncryptedPayload {
    pub payload: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct SecretId(pub String);

#[derive(Deserialize, Serialize)]
pub struct CreateSecretRequest {
    pub ciphertext: Vec<u8>,
    pub expires_at: Option<NaiveDateTime>,
    pub max_views: Option<i32>,
}
