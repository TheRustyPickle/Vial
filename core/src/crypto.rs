use anyhow::{Context, Result, anyhow, bail};
use argon2::Argon2;
use argon2::password_hash::SaltString;
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305};

const SALT_LEN: usize = 22;
const NONCE_LEN: usize = 24;

pub fn encrypt_with_password(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let mut key_buffer = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut key_buffer,
        )
        .map_err(|e| anyhow::anyhow!(e))?;

    // 3. Encrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&key_buffer)
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let salt_bytes = salt.as_str().as_bytes();

    let mut storage = Vec::with_capacity(salt_bytes.len() + NONCE_LEN + ciphertext.len());
    storage.extend_from_slice(salt_bytes);
    storage.extend_from_slice(&nonce);
    storage.extend_from_slice(&ciphertext);

    Ok(storage)
}

pub fn decrypt_with_password(encrypted_blob: &[u8], password: &str) -> Result<Vec<u8>> {
    if encrypted_blob.len() < (SALT_LEN + NONCE_LEN) {
        bail!("Data is too short to be valid");
    }

    let salt_str = std::str::from_utf8(&encrypted_blob[0..SALT_LEN])
        .context("Failed to parse salt as UTF-8")?;

    let nonce_bytes = &encrypted_blob[SALT_LEN..(SALT_LEN + NONCE_LEN)];
    let ciphertext = &encrypted_blob[(SALT_LEN + NONCE_LEN)..];

    let argon2 = Argon2::default();
    let mut key_buffer = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt_str.as_bytes(), &mut key_buffer)
        .map_err(|e| anyhow::anyhow!(e))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key_buffer)
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed (Wrong password?)"))?;

    Ok(plaintext)
}

pub fn encrypt_with_random_key(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);

    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut storage = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    storage.extend_from_slice(&nonce);
    storage.extend_from_slice(&ciphertext);

    Ok((storage, key.into()))
}

pub fn decrypt_with_random_key(encrypted_blob: &[u8], key_bytes: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted_blob.len() < NONCE_LEN {
        bail!("Data is too short to contain a nonce");
    }

    let nonce_bytes = &encrypted_blob[0..NONCE_LEN];
    let ciphertext = &encrypted_blob[NONCE_LEN..];

    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed (Invalid key or corrupted data)"))?;

    Ok(plaintext)
}
