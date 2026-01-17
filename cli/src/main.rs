use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Utc};
use clap::{Parser, Subcommand};
use std::fs::read;
use std::io::{Write as _, stdin, stdout};
use std::path::{Path, PathBuf};
use vial_core::crypto::{
    decrypt_with_password, decrypt_with_random_key, encrypt_with_password, encrypt_with_random_key,
};
use vial_shared::{
    CreateSecretRequest, EncryptedPayload, FullSecretV1, Payload, SecretFileV1, SecretId,
    sanitize_filename,
};

const MAX_SIZE: usize = 1024 * 1024 * 5 + 200;

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

        /// Encrypt the secret using a user-provided password
        ///
        /// When set, you will be prompted for a password which
        /// is used to encrypt the secret.
        ///
        /// If not set, a random key is generated automatically
        /// and embedded into the returned link after the '#'.
        #[arg(short = 'p', long)]
        password: bool,

        /// Attach one or more files to the secret
        ///
        /// May be specified multiple times:
        ///   -a file1.txt -a image.png
        ///
        /// Attached files are encrypted together with the text
        /// and restored on receipt.
        #[arg(short = 'a', long = "attach", value_name = "PATH")]
        attachments: Vec<PathBuf>,
    },

    /// Retrieve a secret from the server
    Recv {
        /// Secret identifier or full URL
        ///
        /// This may be a raw secret ID (e.g. abc123)
        /// or a full URL returned by the `send` command.
        #[arg(long, value_name = "ID|URL")]
        source: String,

        /// Decrypt using a user-provided password
        ///
        /// If the provided source does not contain a '#<key>'
        /// fragment, you will be prompted for a password and
        /// the secret will be decrypted using the password-based
        /// encryption scheme.
        ///
        /// This is the default behavior when no key is found.
        #[arg(short = 'p', long)]
        password: bool,

        /// Decrypt using a random key provided manually
        ///
        /// Use this when the secret was encrypted with a random
        /// key and the link does not include the '#<key>' fragment.
        ///
        /// You will be prompted to enter the key manually.
        #[arg(short = 'r', long)]
        random_key: bool,
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
            password,
            attachments,
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

            let mut files = Vec::with_capacity(attachments.len());

            for path in attachments {
                if !path.is_file() {
                    continue;
                }

                let content = read(&path)?;
                let filename = path.file_name().unwrap().to_string_lossy().to_string();

                files.push(log_err(
                    SecretFileV1::new(filename, content),
                    "Failed to serialize file",
                )?);
            }

            let to_encrypt = FullSecretV1 { text, files }
                .to_payload()
                .map_err(|e| {
                    println!("Failed to serialize secret: {e}");
                    e
                })?
                .to_bytes()
                .map_err(|e| {
                    println!("Failed to serialize secret: {e}");
                    e
                })?;

            let (blob, key) = if password {
                let key = log_err(
                    rpassword::prompt_password("Enter password: "),
                    "Failed to read the password",
                )?;

                let blob = log_err(
                    encrypt_with_password(&to_encrypt, &key),
                    "Failed to encrypt",
                )?;

                (blob, None)
            } else {
                let (blob, key) =
                    log_err(encrypt_with_random_key(&to_encrypt), "Failed to encrypt")?;

                (blob, Some(key))
            };

            if blob.len() > MAX_SIZE {
                println!(
                    "The secret is too large to be sent. Try breaking it up. Max limit is {MAX_SIZE} bytes."
                );
            }

            let secret_request = CreateSecretRequest {
                ciphertext: blob,
                expires_at,
                max_views,
            };

            let client = reqwest::blocking::Client::new();

            let secret_id: SecretId = log_err(
                reqwest_json(client.post(PAYLOAD_URL).json(&secret_request)),
                "Failed to create secret",
            )?;

            let secret_link = if password {
                format!("{PAYLOAD_URL}/{}", secret_id.0)
            } else {
                let key_b64 = URL_SAFE.encode(key.unwrap());

                format!("{PAYLOAD_URL}/{}#{key_b64}", secret_id.0)
            };

            println!("{secret_link}");
        }
        Command::Recv {
            source,
            password,
            random_key,
        } => {
            let Some(secret_id) = source.split('/').next_back() else {
                println!("Could not find the secret id in the secret link.");
                return Ok(());
            };

            let key = source.split_once('#');

            let client = reqwest::blocking::Client::new();

            let payload: EncryptedPayload = log_err(
                reqwest_json(client.get(format!("{PAYLOAD_URL}/{secret_id}"))),
                "Failed to retrieve secret",
            )?;

            let decrypted = if let Some((_, key)) = key {
                decrypt_random_key(key, payload.payload)?
            } else {
                let key = log_err(
                    rpassword::prompt_password("Enter key/password: "),
                    "Failed to get the key",
                )?;

                // If password flag is set, use password
                // If random key flag is set, use random key
                // Otherwise, use password
                if password {
                    decrypt_password(&key, payload.payload)?
                } else if random_key {
                    decrypt_random_key(&key, payload.payload)?
                } else {
                    decrypt_password(&key, payload.payload)?
                }
            };

            println!("{}", decrypted.text);

            for file in decrypted.files {
                log_err(save_file(file), "Failed to save file")?;
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

fn log_err<T, E: std::fmt::Display>(res: Result<T, E>, context: &str) -> Result<T, E> {
    res.map_err(|e| {
        println!("{}: {}", context, e);
        e
    })
}

fn decrypt_random_key(
    key: &str,
    payload: Vec<u8>,
) -> Result<FullSecretV1, Box<dyn std::error::Error>> {
    let decoded_key = log_err(
        URL_SAFE.decode(key),
        "Failed to decode key. Is the key valid",
    )?;

    let arr_ref: &[u8; 32] = log_err(
        decoded_key.as_slice().try_into(),
        "Failed to decode key. Is the key valid",
    )?;

    let decrypted = log_err(
        decrypt_with_random_key(payload.as_slice(), arr_ref),
        "Failed to decrypt secret",
    )?;

    let full_secret = Payload::from_bytes(decrypted)
        .map_err(|e| {
            println!("Failed to deserialize secret: {e}");
            e
        })?
        .to_full_secret()
        .map_err(|e| {
            println!("Failed to deserialize secret: {e}");
            e
        })?;

    Ok(full_secret)
}

fn decrypt_password(
    key: &str,
    payload: Vec<u8>,
) -> Result<FullSecretV1, Box<dyn std::error::Error>> {
    let decrypted = log_err(
        decrypt_with_password(payload.as_slice(), key),
        "Failed to decrypt secret",
    )?;

    let full_secret = Payload::from_bytes(decrypted)
        .map_err(|e| {
            println!("Failed to deserialize secret: {e}");
            e
        })?
        .to_full_secret()
        .map_err(|e| {
            println!("Failed to deserialize secret: {e}");
            e
        })?;

    Ok(full_secret)
}

fn save_file(file: SecretFileV1) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file.filename());

    // If path exists, try to save the file by adding (x) number, at most 10 times.
    // If the attempt fails, ask the user to enter a new filename until a valid one is
    // entered.
    if path.exists() {
        let mut successful = false;

        for i in 0..10 {
            let new_file_name = format!("{} ({})", file.filename(), i + 1);
            let new_path = Path::new(&new_file_name);

            if !new_path.exists() {
                file.write(new_path)?;

                println!("Saved file to {}", new_path.display());
                successful = true;
                break;
            }
        }

        while !successful {
            let mut filename = String::new();
            print!("Could not save file. Enter a new filename: ");
            let _ = stdout().flush();
            stdin().read_line(&mut filename)?;

            let filename = filename.trim();
            let safe_filename = sanitize_filename(filename)?;

            let new_path = Path::new(&safe_filename);

            if new_path.exists() {
                println!("File already exists.");
            } else {
                file.write(new_path)?;

                successful = true;
            }
        }
    } else {
        file.write(path)?;

        println!("Saved file to {}", path.display());
    }

    Ok(())
}
