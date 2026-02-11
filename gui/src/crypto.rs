use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use std::{collections::BTreeSet, fs::read};
use vial_core::crypto::{
    decrypt_with_password, decrypt_with_random_key, encrypt_with_password, encrypt_with_random_key,
};
use vial_shared::{FullSecretV1, SecretFileV1};

pub const MAX_SIZE: usize = 1024 * 1024 * 5 + 200;
pub const DEFAULT_SERVER_URL: &str = "https://rustypickle.onrender.com/api/secrets";
pub const DEFAULT_WEB_URL: &str = "https://rustypickle.onrender.com/secrets";

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

pub struct Params {
    pub max_size: usize,
    pub server_url: String,
    pub web_ui_url: String,
}

pub struct ToEncrypt {
    text: String,
    files: BTreeSet<PathBuf>,
    schema: Schema,
    password: Option<String>,
    params: Params,
}

impl ToEncrypt {
    pub fn new(
        text: String,
        files: BTreeSet<PathBuf>,
        schema: Schema,
        password: Option<String>,
        params: Params,
    ) -> Self {
        Self {
            text,
            files,
            schema,
            password,
            params,
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

        if blob.len() > self.params.max_size {
            return Err(anyhow!(
                "The secret is too large to be sent. Try breaking it up. Max limit is {} bytes.",
                self.params.max_size
            ));
        }

        Ok(String::from("https://link.com"))
    }
}
