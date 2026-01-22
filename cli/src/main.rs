use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use chrono::{Days, Utc};
use clap::{Args, Parser, Subcommand};
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::env::set_current_dir;
use std::fs::{File, create_dir_all, read};
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
const DEFAULT_SERVER_URL: &str = "https://rustypickle.onrender.com/api/secrets";
const DEFAULT_WEB_URL: &str = "https://rustypickle.onrender.com/secrets";

#[derive(Parser, Debug)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    download_path: Option<PathBuf>,
    server_url: Option<String>,
    max_size: Option<usize>,
    web_ui_url: Option<String>,
}

impl Config {
    fn get_config() -> Result<Self> {
        let mut target_path = config_dir().unwrap();

        target_path.push("Vial");

        create_dir_all(&target_path)?;

        target_path.push("vial.json");

        if target_path.exists() {
            let contents = read(target_path)?;
            Ok(serde_json::from_slice(&contents)?)
        } else {
            let config = Config {
                download_path: None,
                server_url: None,
                max_size: None,
                web_ui_url: None,
            };

            config.save_config()?;

            Ok(config)
        }
    }

    fn set_download_path(&mut self, path: PathBuf) -> Result<()> {
        self.download_path = Some(path);

        self.save_config()?;

        Ok(())
    }

    fn set_server_url(&mut self, url: String) -> Result<()> {
        self.server_url = Some(url);

        self.save_config()?;

        Ok(())
    }

    fn set_web_ui_url(&mut self, url: String) -> Result<()> {
        self.web_ui_url = Some(url);

        self.save_config()?;

        Ok(())
    }

    fn set_max_size(&mut self, size: usize) -> Result<()> {
        self.max_size = Some(size);

        self.save_config()?;

        Ok(())
    }

    fn save_config(&self) -> Result<()> {
        let mut target_path = config_dir().unwrap();

        target_path.push("Vial");

        target_path.push("vial.json");

        let mut file = File::create(target_path)?;
        serde_json::to_writer(&mut file, self)?;
        Ok(())
    }
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

    let config = Config::get_config()
        .context("Failed to read config")
        .unwrap_or_default();

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
    let max_size = if let Some(max_size) = config.max_size
        && let Some(url) = &config.server_url
        && url != DEFAULT_SERVER_URL
    {
        max_size
    } else {
        MAX_SIZE
    };

    let post_url = if let Some(url) = config.server_url {
        url
    } else {
        DEFAULT_SERVER_URL.to_string()
    };

    let web_ui_url = if let Some(url) = config.web_ui_url {
        url
    } else {
        DEFAULT_WEB_URL.to_string()
    };

    if blob.len() > max_size {
        return Err(anyhow!(
            "The secret is too large to be sent. Try breaking it up. Max limit is {max_size} bytes."
        ));
    }

    if blob.len() > MAX_SIZE {
        return Err(anyhow!(
            "The secret is too large to be sent. Try breaking it up. Max limit is {MAX_SIZE} bytes."
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

    let config = Config::get_config()
        .context("Failed to read config")
        .unwrap_or_default();

    let post_url = if let Some(url) = config.server_url {
        url
    } else {
        DEFAULT_SERVER_URL.to_string()
    };

    let key = source.split_once('#');

    let client = reqwest::blocking::Client::new();

    let payload: EncryptedPayload = reqwest_json(client.get(format!("{post_url}/{secret_id}")))
        .context("Failed to fetch the secret")?;

    let decrypted = if let Some((_, key)) = key {
        decrypt_random_key(key, &payload.payload)
            .context("Failed to decrypt using random key schema")?
    } else {
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
    };

    println!("{}", decrypted.text);

    for file in decrypted.files {
        save_file(&file, &config.download_path).context("Failed to save file")?;
    }
    Ok(())
}

fn config(args: ConfigArgs) -> Result<()> {
    let mut config = Config::get_config().context("Failed to get config")?;

    if let Some(dl_path) = args.set_download_path {
        config
            .set_download_path(dl_path.clone())
            .with_context(|| format!("Failed to set new download path {}", dl_path.display()))?;
    }

    if let Some(url) = args.set_server_url {
        config
            .set_server_url(url.clone())
            .with_context(|| format!("Failed to set new server url {}", url))?;
    }

    if let Some(size) = args.set_max_size {
        config
            .set_max_size(size)
            .with_context(|| format!("Failed to set new max size {}", size))?;
    }

    if let Some(url) = args.set_web_url {
        config
            .set_web_ui_url(url.clone())
            .with_context(|| format!("Failed to set new server url {}", url))?;
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

fn save_file(file: &SecretFileV1, download_path: &Option<PathBuf>) -> Result<()> {
    if let Some(path) = download_path {
        set_current_dir(path)
            .with_context(|| format!("Failed to change directory to {}", path.display()))?;
    }

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
                file.write(new_path).map_err(|e| {
                    anyhow!("Failed to save file at path {}: {e}", new_path.display())
                })?;

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
            let safe_filename = sanitize_filename(filename)
                .map_err(|e| anyhow!("Failed to sanitize filename {filename}: {e}"))?;

            let new_path = Path::new(&safe_filename);

            if new_path.exists() {
                println!("File already exists.");
            } else {
                file.write(new_path).map_err(|e| {
                    anyhow!(
                        "Failed to save file at the path {}: {e}",
                        new_path.display()
                    )
                })?;

                successful = true;
            }
        }
    } else {
        file.write(path)
            .map_err(|e| anyhow!("Failed to save file at path {}: {e}", path.display()))?;

        println!("Saved file to {}", path.display());
    }

    Ok(())
}
