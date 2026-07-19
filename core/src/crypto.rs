use aead::Generate;
use anyhow::{Context, Result, anyhow, bail};
use argon2::Params as Argon2Params;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Algorithm, Argon2, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use zeroize::Zeroize;

const BLOB_VERSION: u8 = 1;
const HEADER_LEN: usize = 2;
const ARGON2_PARAMS_LEN: usize = 12;
const SALT_LEN: usize = 22;
const NONCE_LEN: usize = 24;

enum Scheme {
    Password = 1,
    Random = 2,
}

impl Scheme {
    fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Password),
            2 => Some(Self::Random),
            _ => None,
        }
    }
}

fn write_argon2_params(buf: &mut Vec<u8>, m_cost: u32, t_cost: u32, p_cost: u32) {
    buf.extend_from_slice(&m_cost.to_le_bytes());
    buf.extend_from_slice(&t_cost.to_le_bytes());
    buf.extend_from_slice(&p_cost.to_le_bytes());
}

fn read_argon2_params(blob: &[u8]) -> (u32, u32, u32) {
    let m = u32::from_le_bytes(blob[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap());
    let t = u32::from_le_bytes(blob[HEADER_LEN + 4..HEADER_LEN + 8].try_into().unwrap());
    let p = u32::from_le_bytes(blob[HEADER_LEN + 8..HEADER_LEN + 12].try_into().unwrap());
    (m, t, p)
}

pub fn encrypt_with_password(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let params = Argon2Params::default();
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params.clone());

    let salt = SaltString::generate(&mut OsRng);

    let mut key_buffer = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut key_buffer,
        )
        .map_err(|e| anyhow::anyhow!(e))?;

    let cipher = XChaCha20Poly1305::new(&key_buffer.into());
    key_buffer.zeroize();

    let nonce = XNonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let salt_bytes = salt.as_str().as_bytes();

    let cap = HEADER_LEN + ARGON2_PARAMS_LEN + salt_bytes.len() + NONCE_LEN + ciphertext.len();
    let mut storage = Vec::with_capacity(cap);
    storage.push(BLOB_VERSION);
    storage.push(Scheme::Password as u8);
    write_argon2_params(
        &mut storage,
        params.m_cost(),
        params.t_cost(),
        params.p_cost(),
    );
    storage.extend_from_slice(salt_bytes);
    storage.extend_from_slice(&nonce);
    storage.extend_from_slice(&ciphertext);

    Ok(storage)
}

pub fn decrypt_with_password(encrypted_blob: &[u8], password: &str) -> Result<Vec<u8>> {
    const MIN_LEN: usize = HEADER_LEN + ARGON2_PARAMS_LEN + SALT_LEN + NONCE_LEN + 1;

    if encrypted_blob.len() < MIN_LEN {
        bail!("Data is too short to be valid");
    }

    let version = encrypted_blob[0];

    if version != BLOB_VERSION {
        bail!("Unsupported blob version: {version}");
    }

    if !matches!(Scheme::from_u8(encrypted_blob[1]), Some(Scheme::Password)) {
        bail!("Blob is not a password-encrypted secret");
    }

    let (m_cost, t_cost, p_cost) = read_argon2_params(encrypted_blob);
    let params = Argon2Params::new(m_cost, t_cost, p_cost, None)
        .map_err(|e| anyhow::anyhow!("Blob contains invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

    let params_end = HEADER_LEN + ARGON2_PARAMS_LEN;
    let salt_str = std::str::from_utf8(&encrypted_blob[params_end..params_end + SALT_LEN])
        .context("Failed to parse salt as UTF-8")?;

    let nonce_start = params_end + SALT_LEN;
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce_bytes = &encrypted_blob[nonce_start..nonce_end];
    let ciphertext = &encrypted_blob[nonce_end..];

    let mut key_buffer = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_str.as_bytes(), &mut key_buffer)
        .map_err(|e| anyhow::anyhow!(e))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key_buffer)
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
    key_buffer.zeroize();

    let nonce = nonce_bytes
        .try_into()
        .context("Failed to convert nonce to array")?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed (Wrong password?)"))?;

    Ok(plaintext)
}

pub fn encrypt_with_random_key(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let key = Key::generate();
    let cipher = XChaCha20Poly1305::new(&key);

    let nonce = XNonce::generate();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut storage = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
    storage.push(BLOB_VERSION);
    storage.push(Scheme::Random as u8);
    storage.extend_from_slice(&nonce);
    storage.extend_from_slice(&ciphertext);

    Ok((storage, key.into()))
}

pub fn decrypt_with_random_key(encrypted_blob: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted_blob.len() < HEADER_LEN + NONCE_LEN + 1 {
        bail!("Data is too short");
    }

    let version = encrypted_blob[0];

    if version != BLOB_VERSION {
        bail!("Unsupported blob version: {version}");
    }

    if !matches!(Scheme::from_u8(encrypted_blob[1]), Some(Scheme::Random)) {
        bail!("Blob is not a random-key-encrypted secret");
    }

    let nonce_bytes = &encrypted_blob[HEADER_LEN..HEADER_LEN + NONCE_LEN];
    let ciphertext = &encrypted_blob[HEADER_LEN + NONCE_LEN..];

    let key = key_bytes.into();

    let cipher = XChaCha20Poly1305::new(key);
    let nonce = nonce_bytes
        .try_into()
        .context("Failed to convert nonce to array")?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed (Invalid key or corrupted data)"))?;

    Ok(plaintext)
}

pub fn decrypt(encrypted_blob: &[u8], key_or_password: &str) -> Result<Vec<u8>> {
    if encrypted_blob.len() < HEADER_LEN {
        bail!("Data is too short to be valid");
    }

    let version = encrypted_blob[0];

    if version != BLOB_VERSION {
        bail!("Unsupported blob version: {version}");
    }

    match Scheme::from_u8(encrypted_blob[1]) {
        Some(Scheme::Password) => decrypt_with_password(encrypted_blob, key_or_password),
        Some(Scheme::Random) => {
            let mut key_bytes = URL_SAFE
                .decode(key_or_password)
                .context("Failed to decode key (expected base64-encoded random key)")?;
            let key: &[u8; 32] = key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Key must be exactly 32 bytes. Got {}", key_bytes.len()))?;
            let result = decrypt_with_random_key(encrypted_blob, key)?;
            key_bytes.zeroize();
            Ok(result)
        }
        None => bail!("Unknown scheme byte: {}", encrypted_blob[1]),
    }
}
