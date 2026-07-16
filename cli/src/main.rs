use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Utc};
use clap::{Args, Parser, Subcommand};
use std::fs::read;
use std::io::{Write as _, stdin, stdout};
use std::path::{Path, PathBuf};
use vial_core::crypto::{
    decrypt_with_password, decrypt_with_random_key, encrypt_with_password, encrypt_with_random_key,
};
use vial_shared::config::Config;
use vial_shared::{
    CreateSecretRequest, EncryptedPayload, FullSecretV1, Payload, SecretFile, SecretFileV1,
    SecretId,
};

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send a new secret to the server
    #[command(arg_required_else_help = true)]
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
    #[command(arg_required_else_help = true)]
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

    /// Show or configure the current configuration
    #[command(arg_required_else_help = true)]
    Config(ConfigArgs),
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// Show the current configuration and exit
    ///
    /// Prints all resolved configuration values, including defaults.
    #[arg(short, long)]
    pub show: bool,

    /// Set the default download directory for received files
    ///
    /// Defaults to the current working directory.
    /// The directory will be created if it does not exist.
    #[arg(long, value_name = "PATH")]
    pub set_download_path: Option<PathBuf>,

    /// Set the secrets API base URL
    ///
    /// This must be the endpoint that accepts:
    ///
    /// POST to create a new secret
    ///
    /// GET /{id} to retrieve an existing secret
    ///
    /// Example:
    ///   http://127.0.0.1:8080/secrets
    ///
    /// Defaults to https://rustypickle.onrender.com/api/secrets
    #[arg(long, value_name = "URL")]
    pub set_server_url: Option<String>,

    /// Set the secrets web UI base URL
    ///
    /// This must be an endpoint that accepts:
    ///
    /// /{id} parameter
    ///
    /// Example:
    ///   http://127.0.0.1:8080/secrets
    ///
    /// Defaults to https://rustypickle.onrender.com/secrets
    #[arg(long, value_name = "URL")]
    pub set_web_url: Option<String>,

    /// Set the maximum allowed secret size (in bytes).
    ///
    /// Unless a different server is used than the default one, this value is ignored.
    ///
    /// Defaults to 5 MB plus a small overhead for encryption metadata.
    ///
    /// Example values:
    /// 5242880 (5 MB)
    /// 10485760 (10 MB)
    #[arg(long, value_name = "BYTES")]
    pub set_max_size: Option<usize>,

    /// Set the maximum views allowed for a secret
    ///
    /// Unless a different server is used than the default one, this value is ignored.
    ///
    /// Defaults to 1000 views.
    ///
    /// Example values:
    /// 1000
    /// 9999
    #[arg(long, value_name = "VIEW COUNT")]
    pub set_max_views: Option<usize>,

    /// Set the maximum days a secret is allowed to exist
    ///
    /// Unless a different server is used than the default one, this value is ignored.
    ///
    /// Defaults to 30 days.
    ///
    /// Example values:
    /// 100
    /// 365
    #[arg(long, value_name = "DAYS COUNT")]
    pub set_max_days: Option<usize>,

    /// Set the database URL to use when starting the server bin (vial-server)
    ///
    /// Defaults nothing
    ///
    /// Example value:
    /// postgresql://postgres:asdf@127.0.0.1:5432/asdf
    #[arg(long, value_name = "POSTGRES URL")]
    pub set_database_url: Option<String>,

    /// Set the port to bind to when starting the server bin (vial-server)
    ///
    /// Defaults to 8080.
    ///
    /// Example value:
    /// 8080
    #[arg(long, value_name = "PORT")]
    pub set_port: Option<u16>,

    /// Set the address to bind to when starting the server bin (vial-server)
    ///
    /// Defaults to 127.0.0.1.
    ///
    /// Example value:
    /// 127.0.0.1
    #[arg(long, value_name = "ADDRESS")]
    pub set_address: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Send {
            text,
            view_count,
            expire,
            password,
            attachments,
        } => send(text, view_count, expire, password, attachments)?,
        Command::Recv {
            source,
            password,
            random_key,
        } => receive(source, password, random_key)?,
        Command::Config(args) => {
            config(args)?;
        }
    }

    Ok(())
}

fn send(
    text: String,
    view_count: Option<i32>,
    expire: Option<i32>,
    password: bool,
    attachments: Vec<PathBuf>,
) -> Result<()> {
    if view_count.is_none() && expire.is_none() {
        return Err(anyhow!(
            "At least one of --view-count or --expire must be provided"
        ));
    }

    let mut expires_at = None;
    let mut max_views = None;

    if let Some(view_count) = view_count {
        if !(1..=1000).contains(&view_count) {
            return Err(anyhow!("--view-count must be between 1 and 1000"));
        }
        max_views = Some(view_count);
    }

    if let Some(expire) = expire {
        if !(1..=30).contains(&expire) {
            return Err(anyhow!("--expire must be between 1 and 30"));
        }

        expires_at = Some(Utc::now().naive_utc() + Days::new(expire as u64));
    }

    let config = Config::get_config();

    let mut files = Vec::with_capacity(attachments.len());

    for path in attachments {
        if !path.is_file() {
            continue;
        }

        let content = read(&path)?;
        let filename = path.file_name().unwrap().to_string_lossy().to_string();

        files.push(
            SecretFileV1::new(&filename, content)
                .map_err(|e| anyhow!("Failed to serialize the attachment: {e}"))?,
        );
    }

    let to_encrypt = FullSecretV1 { text, files }
        .to_payload()
        .context("Failed to serialize secret")?
        .to_bytes()
        .context("Failed to serialize secret")?;

    let (blob, key) = if password {
        let key = rpassword::prompt_password("Enter password: ")
            .context("Failed to read the password")?;

        let blob = encrypt_with_password(&to_encrypt, &key)
            .context("Failed to encrypt with the given password")?;

        (blob, None)
    } else {
        let (blob, key) = encrypt_with_random_key(&to_encrypt)
            .context("Failed to encrypt with the random key schema")?;

        (blob, Some(key))
    };

    // Only accept the size in the config if a different server is used than the default one
    let max_size = config.get_max_size_verified();

    let post_url = config.get_server_url();

    let web_ui_url = config.get_web_ui_url();

    if blob.len() > max_size {
        return Err(anyhow!(
            "The secret is too large to be sent. Try breaking it up. Max limit is {max_size} bytes."
        ));
    }

    let secret_request = CreateSecretRequest {
        ciphertext: blob,
        expires_at,
        max_views,
    };

    let client = reqwest::blocking::Client::new();

    let secret_id: SecretId = reqwest_json(client.post(&post_url).json(&secret_request))
        .context("Failed to create new secret")?;

    let secret_link = if password {
        format!("{web_ui_url}/{}", secret_id.0)
    } else {
        let key_b64 = URL_SAFE.encode(key.unwrap());

        format!("{web_ui_url}/{}#{key_b64}", secret_id.0)
    };

    println!("{secret_link}");

    Ok(())
}

fn receive(source: String, password: bool, random_key: bool) -> Result<()> {
    let Some(secret_id) = source.split('/').next_back() else {
        return Err(anyhow!("Could not find the secret id in the secret link."));
    };

    if secret_id.is_empty() || secret_id.contains(' ') {
        return Err(anyhow!("Could not find the secret id in the secret link."));
    }

    let config = Config::get_config();

    let server_url = config.get_server_url();

    let key = secret_id.split_once('#');

    let client = reqwest::blocking::Client::new();

    let decrypted = if let Some((id, key)) = key {
        let payload: EncryptedPayload = reqwest_json(client.get(format!("{server_url}/{id}")))
            .context("Failed to fetch the secret")?;

        decrypt_random_key(key, &payload.payload)
            .context("Failed to decrypt using random key schema")?
    } else {
        let payload: EncryptedPayload =
            reqwest_json(client.get(format!("{server_url}/{secret_id}")))
                .context("Failed to fetch the secret")?;

        let key = rpassword::prompt_password("Enter key/password: ")
            .context("Failed to read the password")?;

        // If password flag is set, use password
        // If random key flag is set, use random key
        // Otherwise, use password
        if password {
            decrypt_password(&key, &payload.payload)
                .context("Failed to decrypt using password schema")?
        } else if random_key {
            decrypt_random_key(&key, &payload.payload)
                .context("Failed to decrypt using random key schema")?
        } else {
            decrypt_password(&key, &payload.payload)
                .context("Failed to decrypt using password schema")?
        }
    }
    .into_shared();

    println!("{}", decrypted.text);

    for file in decrypted.files {
        save_file(&file, &config.download_path).context("Failed to save file")?;
    }
    Ok(())
}

fn config(args: ConfigArgs) -> Result<()> {
    let mut config = Config::get_config();

    if let Some(dl_path) = args.set_download_path {
        config
            .set_download_path(dl_path.clone())
            .with_context(|| format!("Failed to set new download path {}", dl_path.display()))?;
    }

    if let Some(url) = args.set_server_url {
        config
            .set_server_url(url.clone())
            .with_context(|| format!("Failed to set new server url {url}"))?;
    }

    if let Some(size) = args.set_max_size {
        config
            .set_max_size(size)
            .with_context(|| format!("Failed to set new max size {size}"))?;
    }

    if let Some(url) = args.set_web_url {
        config
            .set_web_ui_url(url.clone())
            .with_context(|| format!("Failed to set new server url {url}"))?;
    }

    if let Some(days) = args.set_max_days {
        config
            .set_max_days(days)
            .with_context(|| format!("Failed to set new max days {days}"))?;
    }

    if let Some(views) = args.set_max_views {
        config
            .set_max_views(views)
            .with_context(|| format!("Failed to set new max views {views}"))?;
    }

    if let Some(url) = args.set_database_url {
        config
            .set_database_url(url.clone())
            .with_context(|| format!("Failed to set new database url {url}"))?;
    }

    if let Some(port) = args.set_port {
        config
            .set_port(port)
            .with_context(|| format!("Failed to set new port {port}"))?;
    }

    if let Some(address) = args.set_address {
        config
            .set_address(address.clone())
            .with_context(|| format!("Failed to set new address {address}"))?;
    }

    if args.show {
        println!(
            "{}",
            serde_json::to_string_pretty(&config).context("Failed to serialize config")?
        );
    }

    Ok(())
}

fn reqwest_json<T: serde::de::DeserializeOwned>(
    req: reqwest::blocking::RequestBuilder,
) -> Result<T, reqwest::Error> {
    req.send()?.error_for_status()?.json()
}

fn decrypt_random_key(key: &str, payload: &[u8]) -> Result<FullSecretV1> {
    let decoded_key = URL_SAFE
        .decode(key)
        .context("Failed to decode key. Is the key valid?")?;

    let arr_ref: &[u8; 32] = decoded_key
        .as_slice()
        .try_into()
        .context("Failed to decode key. Is the key valid")?;

    let decrypted =
        decrypt_with_random_key(payload, arr_ref).context("Failed to decrypt secret")?;

    let full_secret = Payload::from_bytes(decrypted)
        .context("Failed to deserialize secret")?
        .to_full_secret()
        .context("Failed to deserialize secret")?;

    Ok(full_secret)
}

fn decrypt_password(key: &str, payload: &[u8]) -> Result<FullSecretV1> {
    let decrypted = decrypt_with_password(payload, key).context("Failed to decrypt secret")?;

    let full_secret = Payload::from_bytes(decrypted)
        .context("Failed to serialize secret")?
        .to_full_secret()
        .context("Failed to serialize secret")?;

    Ok(full_secret)
}

fn save_file(file: &SecretFile, download_path: &Option<PathBuf>) -> Result<()> {
    let base_dir = download_path.clone().unwrap_or_default();
    let mut path = base_dir.join(file.filename());

    if path.exists() {
        let mut input = String::new();
        let suggested = numbered_filename(file.filename(), 1);
        print!(
            "'{path}' already exists. Enter filename [{suggested}]: ",
            path = path.display()
        );
        let _ = stdout().flush();
        stdin().read_line(&mut input)?;

        let chosen = input.trim();
        path = base_dir.join(if chosen.is_empty() {
            &suggested
        } else {
            chosen
        });
    }

    file.write(&path)
        .map_err(|e| anyhow!("Failed to save file at path {}: {e}", path.display()))?;

    println!("Saved file to {}", path.display());
    Ok(())
}

/// Turns `file.txt` into `file (1).txt` instead of `file.txt (1)`
fn numbered_filename(filename: &str, number: usize) -> String {
    let path = Path::new(filename);

    match (
        path.file_stem().and_then(|s| s.to_str()),
        path.extension().and_then(|e| e.to_str()),
    ) {
        (Some(stem), Some(ext)) => format!("{stem} ({number}).{ext}"),
        _ => format!("{filename} ({number})"),
    }
}
