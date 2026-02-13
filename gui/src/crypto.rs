use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Utc};
use std::path::PathBuf;
use std::{collections::BTreeSet, fs::read};
use vial_core::crypto::{encrypt_with_password, encrypt_with_random_key};
use vial_shared::{CreateSecretRequest, FullSecretV1, SecretFileV1, SecretId};

#[derive(Clone, Copy)]
pub enum Schema {
    Random,
    Password,
}

impl Schema {
    pub fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Random,
            1 => Self::Password,
            _ => unreachable!(),
        }
    }
}

pub struct Urls {
    pub server_url: String,
    pub web_ui_url: String,
}

pub struct ToEncrypt {
    text: String,
    files: BTreeSet<PathBuf>,
    schema: Schema,
    password: Option<String>,
    params: Urls,
    max_days: Option<usize>,
    max_view: Option<i32>,
}

impl ToEncrypt {
    pub fn new(
        text: String,
        files: BTreeSet<PathBuf>,
        schema: Schema,
        password: Option<String>,
        params: Urls,
        max_days: Option<usize>,
        max_view: Option<i32>,
    ) -> Self {
        Self {
            text,
            files,
            schema,
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

        let (blob, key) = match self.schema {
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

        let response: SecretId = reqwest::blocking::Client::new()
            .post(self.params.server_url)
            .json(&secret_request)
            .send()
            .context("Failed to send the request")?
            .error_for_status()
            .context("Failed to send the request")?
            .json()
            .context("Failed to parse the response")?;

        let secret_link = if let Schema::Password = self.schema {
            format!("{}/{}", self.params.web_ui_url, response.0)
        } else {
            let key_b64 = URL_SAFE.encode(key.unwrap());

            format!("{}/{}#{key_b64}", self.params.web_ui_url, response.0)
        };

        Ok(secret_link)
    }
}
