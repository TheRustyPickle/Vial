use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Utc};
use clap::{Parser, Subcommand};
use vial_core::crypto::{decrypt_with_random_key, encrypt_with_random_key};
use vial_shared::{CreateSecretRequest, EncryptedPayload, SecretId};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send a new secret to the server
    Send {
        /// The secret content to store
        ///
        /// This can be any UTF-8 text. Consider quoting the value
        /// if it contains spaces or special characters.
        #[arg(short, long, value_name = "TEXT")]
        text: String,

        /// Maximum number of times the secret can be viewed
        ///
        /// Must be between 1 and 1000. If omitted, the secret
        /// will not expire based on view count.
        #[arg(short = 'v', long, value_name = "COUNT")]
        view_count: Option<i32>,

        /// Number of days the secret remains valid
        ///
        /// Must be a positive integer up to 30. If omitted,
        /// the secret will not expire based on time.
        #[arg(short = 'e', long, value_name = "DAYS")]
        expire: Option<i32>,
    },

    /// Retrieve a secret from the server
    Recv {
        /// Secret identifier or full URL
        ///
        /// This may be a raw secret ID (e.g. abc123)
        /// or a full URL returned by the `send` command.
        #[arg(long, value_name = "ID|URL")]
        source: String,
    },
}

const PAYLOAD_URL: &str = "http://127.0.0.1:8080/secrets";

fn main() {
    let cli = Cli::parse();

    let _ = run(cli);
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Send {
            text,
            view_count,
            expire,
        } => {
            if view_count.is_none() && expire.is_none() {
                println!("At least one of --view-count or --expire must be provided");
                return Ok(());
            }

            let mut expires_at = None;
            let mut max_views = None;

            if let Some(view_count) = view_count {
                if !(1..=1000).contains(&view_count) {
                    println!("--view-count must be between 1 and 1000");
                    return Ok(());
                }
                max_views = Some(view_count);
            }

            if let Some(expire) = expire {
                if !(1..=30).contains(&expire) {
                    println!("--expire must be between 1 and 30");
                    return Ok(());
                }

                expires_at = Some(Utc::now().naive_utc() + Days::new(expire as u64));
            }

            let (blob, key) = encrypt_with_random_key(text.as_bytes()).map_err(|e| {
                println!("Failed to encrypt text: {e}");
                e
            })?;

            let secret_request = CreateSecretRequest {
                ciphertext: blob,
                expires_at,
                max_views,
            };

            let client = reqwest::blocking::Client::new();

            let secret_id: SecretId = reqwest_json(client.post(PAYLOAD_URL).json(&secret_request))
                .map_err(|e| {
                    println!("Failed to create secret: {e}");
                    e
                })?;

            let key_b64 = URL_SAFE.encode(key);

            let secret_link = format!("{PAYLOAD_URL}/{}#{key_b64}", secret_id.0);

            println!("{secret_link}");
        }
        Command::Recv { source } => {
            let Some(secret_id) = source.split("/").last() else {
                println!("Could not find the secret id in the secret link.");
                return Ok(());
            };

            let key = source.split("#").last();

            let client = reqwest::blocking::Client::new();

            let payload: EncryptedPayload =
                reqwest_json(client.get(format!("{PAYLOAD_URL}/{secret_id}"))).map_err(|e| {
                    println!("Failed to retrieve secret: {e}");
                    e
                })?;

            if let Some(key) = key {
                let decoded_key = URL_SAFE.decode(key).map_err(|e| {
                    println!("Failed to decode key. Is the key valid? {e}");
                    e
                })?;

                let arr_ref: &[u8; 32] = decoded_key.as_slice().try_into().inspect_err(|&e| {
                    println!("Failed to decode key. Is the key valid? {e}");
                })?;

                let decrypted = decrypt_with_random_key(payload.payload.as_slice(), arr_ref)
                    .map_err(|e| {
                        println!("Failed to decrypt secret: {e}");
                        e
                    })?;

                let utf8_text = String::from_utf8(decrypted).map_err(|e| {
                    println!("Failed to decode decrypted text: {e}");
                    e
                })?;

                println!("Decrypted: {utf8_text}");
            }
        }
    }
    Ok(())
}

fn reqwest_json<T: serde::de::DeserializeOwned>(
    req: reqwest::blocking::RequestBuilder,
) -> Result<T, reqwest::Error> {
    req.send()?.error_for_status()?.json()
}
