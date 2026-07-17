use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Utc};
use reqwest::blocking::Client;
use std::path::PathBuf;
use std::{collections::BTreeSet, fs::read};
use vial_core::crypto::{decrypt, encrypt_with_password, encrypt_with_random_key};
use vial_shared::{
    CreateSecretRequest, EncryptedPayload, FullSecret, FullSecretV1, Payload, SecretFileV1,
    SecretId,
};

#[derive(Clone, Copy)]
pub enum Schema {
    Password,
    Random,
}

impl Schema {
    pub fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Password,
            1 => Self::Random,
            _ => unreachable!(),
        }
    }
}

pub struct Commons {
    pub server_url: String,
    pub web_ui_url: String,
    pub schema: Option<Schema>,
}

pub struct ToEncrypt {
    text: String,
    files: BTreeSet<PathBuf>,
    password: Option<String>,
    params: Commons,
    max_days: Option<usize>,
    max_view: Option<i32>,
}

pub struct ToDecrypt {
    id: String,
    key: String,
    params: Commons,
}

impl ToEncrypt {
    pub fn new(
        text: String,
        files: BTreeSet<PathBuf>,
        password: Option<String>,
        params: Commons,
        max_days: Option<usize>,
        max_view: Option<i32>,
    ) -> Self {
        Self {
            text,
            files,
            password,
            params,
            max_days,
            max_view,
        }
    }

    pub fn create_secret(self) -> Result<String> {
        let mut files = Vec::with_capacity(self.files.len());

        for path in &self.files {
            if !path.is_file() {
                continue;
            }

            let content = read(path)?;
            let filename = path.file_name().unwrap().to_string_lossy().to_string();

            files.push(
                SecretFileV1::new(&filename, content)
                    .map_err(|e| anyhow!("Failed to serialize the attachment: {e}"))?,
            );
        }

        let to_encrypt = FullSecretV1 {
            text: self.text,
            files,
        }
        .to_payload()
        .context("Failed to serialize secret")?
        .to_bytes()
        .context("Failed to serialize secret")?;

        let schema = self.params.schema.unwrap();

        let (blob, key) = match schema {
            Schema::Password => {
                let password = self.password.ok_or(anyhow!("Password is required"))?;

                if password.is_empty() {
                    return Err(anyhow!("Password cannot be empty"));
                }

                let blob = encrypt_with_password(&to_encrypt, &password)
                    .context("Failed to encrypt with the given password")?;

                (blob, None)
            }
            Schema::Random => {
                let (blob, key) = encrypt_with_random_key(&to_encrypt)
                    .context("Failed to encrypt with the random key schema")?;

                (blob, Some(key))
            }
        };

        let expires_at = self
            .max_days
            .map(|days| Utc::now().naive_utc() + Days::new(days as u64));

        let max_views = self.max_view;

        let secret_request = CreateSecretRequest {
            ciphertext: blob,
            expires_at,
            max_views,
        };

        let response: SecretId = Client::new()
            .post(self.params.server_url)
            .json(&secret_request)
            .send()
            .context("Failed to send the request")?
            .error_for_status()
            .context("Failed to send the request")?
            .json()
            .context("Failed to parse the response")?;

        let secret_link = if let Schema::Password = schema {
            format!("{}/{}", self.params.web_ui_url, response.0)
        } else {
            let key_b64 = URL_SAFE.encode(key.unwrap());

            format!("{}/{}#{key_b64}", self.params.web_ui_url, response.0)
        };

        Ok(secret_link)
    }
}

impl ToDecrypt {
    pub fn new(id: String, key: String, params: Commons) -> Self {
        Self { id, key, params }
    }

    pub fn decrypt_secret(self) -> Result<FullSecret> {
        let client = Client::new();

        let response: EncryptedPayload = client
            .get(format!("{}/{}", self.params.server_url, self.id))
            .send()
            .context("Failed to send the request")?
            .error_for_status()
            .context("Failed to send the request")?
            .json()
            .context("Failed to parse the response")?;

        let bytes = decrypt(&response.payload, &self.key).context("Failed to decrypt secret")?;

        let result = Payload::from_bytes(bytes)
            .context("Failed to deserialize secret")?
            .to_full_secret()
            .context("Failed to deserialize secret")?;

        Ok(result.into_shared())
    }
}
