use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use std::{collections::BTreeSet, fs::read};
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

pub struct ToEncrypt {
    text: String,
    files: BTreeSet<PathBuf>,
    schema: Schema,
    password: Option<String>,
}

impl ToEncrypt {
    pub fn new(
        text: String,
        files: BTreeSet<PathBuf>,
        schema: Schema,
        password: Option<String>,
    ) -> Self {
        Self {
            text,
            files,
            schema,
            password,
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

        Ok(String::from("https://link.com"))
    }
}
