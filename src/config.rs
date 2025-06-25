use anyhow::{anyhow, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_key_id: String,
    pub api_key_secret: String,
    pub tenant_url: String,
}

impl Config {
    pub async fn load() -> Result<Self> {
        let config_path = get_config_path()?;

        if !config_path.exists() {
            return Err(anyhow!(
                "Configuration file not found. Run with --init-config to set up credentials."
            ));
        }

        let content = fs::read_to_string(config_path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub async fn save(&self) -> Result<()> {
        let config_path = get_config_path()?;

        // Create directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        Ok(())
    }
}

pub async fn init_config() -> Result<()> {
    println!("Initialising XDRTop configuration...");

    print!("Enter API Key ID: ");
    io::stdout().flush()?;
    let mut api_key_id = String::new();
    io::stdin().read_line(&mut api_key_id)?;
    let api_key_id = api_key_id.trim().to_string();

    print!("Enter API Key Secret: ");
    io::stdout().flush()?;
    let mut api_key_secret = String::new();
    io::stdin().read_line(&mut api_key_secret)?;
    let api_key_secret = api_key_secret.trim().to_string();

    print!("Enter Tenant URL (e.g., https://api-your-tenant.xdr.us.paloaltonetworks.com): ");
    io::stdout().flush()?;
    let mut tenant_url = String::new();
    io::stdin().read_line(&mut tenant_url)?;
    let tenant_url = tenant_url.trim().to_string();

    let config = Config {
        api_key_id,
        api_key_secret,
        tenant_url,
    };

    config.save().await?;
    println!("Configuration saved successfully!");
    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow!("Unable to find home directory"))?;
    Ok(home.join(".xdrtop").join("config.json"))
}
