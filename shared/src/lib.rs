use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

/// Received via HTTPS from the server then decrypted to Payload struct
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct EncryptedPayload {
    pub payload: Vec<u8>,
}

/// Gets returned by the server when creating a new secret
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SecretId(pub String);

/// Sent to the server when creating a new secret
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CreateSecretRequest {
    pub ciphertext: Vec<u8>,
    pub expires_at: Option<NaiveDateTime>,
    pub max_views: Option<i32>,
}

/// Once the bytes gets decrypted, should be deserialized to this struct.
/// Similarly, before encrypting, this struct is serialized to bytes.
///
/// After deserializing, the bytes can be deserialized to `FullSecretV1` struct.
/// Similarly, payload is generated from the serialized `FullSecretV1` struct.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Payload {
    pub version: u8,
    pub payload: Vec<u8>,
}

impl Payload {
    pub fn new(full_secret: &FullSecretV1) -> Result<Self, postcard::Error> {
        let payload = full_secret.to_bytes()?;
        Ok(Self {
            payload,
            version: 1,
        })
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, postcard::Error> {
        postcard::from_bytes(&bytes)
    }

    pub fn to_full_secret(&self) -> Result<FullSecretV1, postcard::Error> {
        let secret = FullSecretV1::from_bytes(&self.payload)?;
        Ok(secret)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FullSecretV1 {
    pub text: String,
    pub files: Vec<SecretFileV1>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SecretFileV1 {
    filename: String,
    content: Vec<u8>,
}

impl SecretFileV1 {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(filename: &str, content: Vec<u8>) -> Result<Self, Box<dyn std::error::Error>> {
        let safe_filename = sanitize_filename(filename)?;

        if content.is_empty() {
            return Err("File is empty".into());
        }

        Ok(Self {
            filename: safe_filename,
            content,
        })
    }

    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn write(&self, path: &Path) -> Result<(), std::io::Error> {
        std::fs::write(path, self.content())?;
        Ok(())
    }
}

impl FullSecretV1 {
    fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    pub fn to_payload(&self) -> Result<Payload, postcard::Error> {
        let payload = self.to_bytes()?;
        Ok(Payload {
            version: 1,
            payload,
        })
    }

    #[must_use]
    pub fn total_files(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn into_shared(self) -> FullSecret {
        FullSecret {
            text: Arc::new(self.text),
            files: self
                .files
                .into_iter()
                .map(|f| SecretFile {
                    filename: f.filename,
                    content: Arc::new(f.content),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FullSecret {
    pub text: Arc<String>,
    pub files: Vec<SecretFile>,
}

#[derive(Clone, Debug)]
pub struct SecretFile {
    pub filename: String,
    pub content: Arc<Vec<u8>>,
}

impl FullSecret {
    #[must_use]
    pub fn total_files(&self) -> usize {
        self.files.len()
    }
}

impl SecretFile {
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.filename
    }

    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn write(&self, path: &Path) -> Result<(), std::io::Error> {
        std::fs::write(path, self.content())?;
        Ok(())
    }
}

/// Helper function to sanitize a filename from potentially unsafe characters
#[cfg(not(target_arch = "wasm32"))]
pub fn sanitize_filename(name: &str) -> Result<String, &'static str> {
    let path = Path::new(name);

    if path.components().count() != 1 {
        return Err("Invalid filename (must not contain path separators)");
    }

    let file_name = path.file_name().ok_or("Invalid filename")?;

    let file_name = file_name.to_str().ok_or("Filename is not valid UTF-8")?;

    if file_name.is_empty() || file_name == "." || file_name == ".." || !path.is_file() {
        return Err("Invalid filename");
    }

    Ok(file_name.to_string())
}
