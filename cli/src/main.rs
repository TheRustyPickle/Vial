use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Timelike, Utc};
use clap::{Parser, Subcommand};
use reqwest::Client;
use vial_core::crypto::{decrypt_with_random_key, encrypt_with_random_key};
use vial_shared::{CreateSecretRequest, SecretId};

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

    match cli.command {
        Command::Send {
            text,
            view_count,
            expire,
        } => {
            if view_count.is_none() && expire.is_none() {
                println!("At least one of --view-count or --expire must be provided");
                return;
            }

            let mut expires_at = None;
            let mut max_views = None;

            if let Some(view_count) = view_count {
                if view_count < 1 || view_count > 1000 {
                    println!("--view-count must be between 1 and 1000");
                    return;
                }
                max_views = Some(view_count);
            }

            if let Some(expire) = expire {
                if expire < 1 || expire > 30 {
                    println!("--expire must be between 1 and 30");
                    return;
                }

                let expires_at = Some(Utc::now().naive_utc() + Days::new(expire as u64));
            }

            let (blob, key) = encrypt_with_random_key(text.as_bytes()).unwrap();

            let secret_request = CreateSecretRequest {
                ciphertext: blob,
                expires_at,
                max_views,
            };

            let client = reqwest::blocking::Client::new();

            let result = client.post(PAYLOAD_URL).json(&secret_request).send();

            if let Err(e) = result {
                println!("Failed to create secret: {e}");
                return;
            }

            let response = result.unwrap().error_for_status();

            if let Err(e) = response {
                println!("Failed to create secret: {e}");
                return;
            }

            let response: Result<SecretId, reqwest::Error> = response.unwrap().json();

            if let Err(e) = response {
                println!("Failed to create secret: {e}");
                return;
            }

            let secret_id = response.unwrap();

            let key_b64 = URL_SAFE.encode(key);

            let secret_link = format!("{PAYLOAD_URL}/{}#{key_b64}", secret_id.0);

            // let blob_b64 = URL_SAFE.encode(blob);

            // println!("Key: {key_b64}");
            // println!("Blob: {blob_b64}");

            // let key = URL_SAFE.decode(&key_b64).unwrap();
            // let blob = URL_SAFE.decode(&blob_b64).unwrap();

            // let arr_ref: &[u8; 32] = key
            //     .as_slice()
            //     .try_into()
            //     .expect("Vector must be exactly 32 bytes");

            // let decrypted = decrypt_with_random_key(blob.as_slice(), arr_ref).unwrap();
            // println!("Decrypted: {}", String::from_utf8(decrypted).unwrap());

            println!("{secret_link}");
        }
        Command::Recv { source } => println!("Receiving from: {}", source),
    }
}
