use anyhow::{Result, anyhow};
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::env::var;
use std::fs::{File, create_dir_all, read};
use std::path::PathBuf;

pub const MAX_SIZE: usize = 1024 * 1024 * 5 + 200;
pub const MAX_DAY_COUNT: usize = 30;
pub const MAX_VIEW_COUNT: usize = 1000;
pub const DEFAULT_SERVER_URL: &str = "https://rustypickle.onrender.com/api/secrets";
pub const DEFAULT_WEB_URL: &str = "https://rustypickle.onrender.com/secrets";

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    /// Path to save downloaded files
    pub download_path: Option<PathBuf>,
    /// The URL where secret create and fetch request is sent
    pub server_url: Option<String>,
    pub max_size: Option<usize>,
    pub web_ui_url: Option<String>,
    pub max_views: Option<usize>,
    pub max_days: Option<usize>,
    pub database_url: Option<String>,
    pub port: Option<u16>,
    pub address: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            download_path: None,
            server_url: Some(DEFAULT_SERVER_URL.to_string()),
            max_size: Some(MAX_SIZE),
            web_ui_url: Some(DEFAULT_WEB_URL.to_string()),
            max_views: Some(MAX_VIEW_COUNT),
            max_days: Some(MAX_DAY_COUNT),
            database_url: None,
            port: Some(8080),
            address: Some("127.0.0.1".to_string()),
        }
    }
}

impl Config {
    #[must_use]
    pub fn get_config() -> Self {
        let result = || -> Result<Config> {
            let mut target_path = config_dir().ok_or(anyhow!("Failed to get config dir"))?;

            target_path.push("Vial");

            create_dir_all(&target_path)?;

            target_path.push("vial.json");
            if target_path.exists() {
                let contents = read(target_path)?;
                Ok(serde_json::from_slice(&contents)?)
            } else {
                let config = Config::default();

                config.save_config()?;

                Ok(config)
            }
        };

        result().unwrap_or_default()
    }

    #[must_use]
    pub fn get_server_url(&self) -> String {
        var("SERVER_URL").unwrap_or(
            self.server_url
                .clone()
                .unwrap_or(DEFAULT_SERVER_URL.to_string()),
        )
    }

    #[must_use]
    pub fn get_web_ui_url(&self) -> String {
        var("WEB_URL").unwrap_or(
            self.server_url
                .clone()
                .unwrap_or(DEFAULT_WEB_URL.to_string()),
        )
    }

    #[must_use]
    pub fn get_max_size(&self) -> usize {
        self.max_size.unwrap_or(MAX_SIZE)
    }

    #[must_use]
    pub fn get_max_size_verified(&self) -> usize {
        let Ok(max_size) = var("MAX_SIZE") else {
            if let Some(server_url) = &self.server_url
                && server_url != DEFAULT_SERVER_URL
            {
                return self.get_max_size();
            }
            return MAX_SIZE;
        };

        max_size.parse().unwrap_or(MAX_SIZE)
    }

    #[must_use]
    pub fn get_max_views(&self) -> usize {
        self.max_views.unwrap_or(MAX_VIEW_COUNT)
    }

    #[must_use]
    pub fn get_max_views_verified(&self) -> usize {
        let Ok(max_views) = var("MAX_VIEW") else {
            if let Some(server_url) = &self.server_url
                && server_url != DEFAULT_SERVER_URL
            {
                return self.get_max_views();
            }
            return MAX_VIEW_COUNT;
        };

        max_views.parse().unwrap_or(MAX_VIEW_COUNT)
    }

    #[must_use]
    pub fn get_max_days(&self) -> usize {
        self.max_days.unwrap_or(MAX_DAY_COUNT)
    }

    #[must_use]
    pub fn get_max_days_verified(&self) -> usize {
        let Ok(max_days) = var("MAX_DAY") else {
            if let Some(server_url) = &self.server_url
                && server_url != DEFAULT_SERVER_URL
            {
                return self.get_max_days();
            }
            return MAX_DAY_COUNT;
        };

        max_days.parse().unwrap_or(MAX_DAY_COUNT)
    }

    #[must_use]
    pub fn get_database_url_verifier(&self) -> String {
        var("DATABASE_URL").unwrap_or(self.database_url.clone().unwrap_or_default())
    }

    #[must_use]
    pub fn get_port(&self) -> u16 {
        var("PORT")
            .map(|p| p.parse().unwrap())
            .unwrap_or(self.port.unwrap_or(8080))
    }

    #[must_use]
    pub fn get_address(&self) -> String {
        var("ADDRESS").unwrap_or(self.address.clone().unwrap_or("127.0.0.1".to_string()))
    }

    pub fn set_download_path(&mut self, path: PathBuf) -> Result<()> {
        self.download_path = Some(path);

        self.save_config()?;

        Ok(())
    }

    pub fn set_server_url(&mut self, url: String) -> Result<()> {
        self.server_url = Some(url);

        self.save_config()?;

        Ok(())
    }

    pub fn set_web_ui_url(&mut self, url: String) -> Result<()> {
        self.web_ui_url = Some(url);

        self.save_config()?;

        Ok(())
    }

    pub fn set_max_size(&mut self, size: usize) -> Result<()> {
        self.max_size = Some(size);

        self.save_config()?;

        Ok(())
    }

    pub fn set_max_views(&mut self, views: usize) -> Result<()> {
        self.max_views = Some(views);

        self.save_config()?;

        Ok(())
    }

    pub fn set_max_days(&mut self, days: usize) -> Result<()> {
        self.max_days = Some(days);

        self.save_config()?;

        Ok(())
    }

    pub fn save_config(&self) -> Result<()> {
        let mut target_path = config_dir().unwrap();

        target_path.push("Vial");

        target_path.push("vial.json");

        let mut file = File::create(target_path)?;
        serde_json::to_writer(&mut file, self)?;
        Ok(())
    }
}
