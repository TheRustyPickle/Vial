## Blob format (v1)

### Password scheme

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Version (`0x01`) |
| 1 | 1 | Scheme (`0x01`) |
| 2 | 4 | Argon2 `m_cost` (KiB), LE |
| 6 | 4 | Argon2 `t_cost` (iterations), LE |
| 10 | 4 | Argon2 `p_cost` (parallelism), LE |
| 14 | 22 | Argon2 salt (base64 salt string bytes) |
| 36 | 24 | XChaCha20-Poly1305 nonce |
| 60 | _ | AEAD ciphertext (includes 16-byte tag) |

Decryption re-derives the 32-byte key using Argon2id with the stored params, then decrypts with XChaCha20-Poly1305.

### Random key scheme

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Version (`0x01`) |
| 1 | 1 | Scheme (`0x02`) |
| 2 | 24 | XChaCha20-Poly1305 nonce |
| 26 | _ | AEAD ciphertext (includes 16-byte tag) |

The 32-byte key is transmitted out-of-band (URL fragment).
