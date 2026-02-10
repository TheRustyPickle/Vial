use anyhow::Result;
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::fs::{File, create_dir_all, read};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub download_path: Option<PathBuf>,
    pub server_url: Option<String>,
    pub max_size: Option<usize>,
    pub web_ui_url: Option<String>,
}

impl Config {
    pub fn get_config() -> Result<Self> {
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

    pub fn save_config(&self) -> Result<()> {
        let mut target_path = config_dir().unwrap();

        target_path.push("Vial");

        target_path.push("vial.json");

        let mut file = File::create(target_path)?;
        serde_json::to_writer(&mut file, self)?;
        Ok(())
    }
}
