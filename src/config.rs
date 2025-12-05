use anyhow::{anyhow, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};

use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_key_id: String,
    pub api_key_secret: String,
    pub tenant_url: String,
    #[serde(default)]
    pub filter_settings: FilterSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilterSettings {
    pub severity_filter: Option<String>,
    pub status_filter: Option<String>,
}

impl Config {
    pub async fn load() -> Result<Self> {
        // First try to load from environment variables (Replit secrets)
        if let Ok(config) = Self::from_env() {
            return Ok(config);
        }

        // Fall back to config file
        let config_path = get_config_path()?;

        if !config_path.exists() {
            return Err(anyhow!(
                "Configuration file not found. Run with --init-config to set up credentials."
            ));
        }

        // Use async file I/O for better performance
        let content = tokio::fs::read_to_string(&config_path).await?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from environment variables (for Replit deployment)
    fn from_env() -> Result<Self> {
        let api_key_id = std::env::var("XDR_API_KEY_ID")
            .map_err(|_| anyhow!("XDR_API_KEY_ID not set"))?;
        let api_key_secret = std::env::var("XDR_API_KEY")
            .map_err(|_| anyhow!("XDR_API_KEY not set"))?;
        let tenant_url = std::env::var("XDR_FQDN")
            .map_err(|_| anyhow!("XDR_FQDN not set"))?;

        // Ensure tenant URL has proper format
        let tenant_url = if tenant_url.starts_with("https://") {
            tenant_url
        } else {
            format!("https://{tenant_url}")
        };

        Ok(Config {
            api_key_id,
            api_key_secret,
            tenant_url,
            filter_settings: FilterSettings::default(),
        })
    }
    
    pub async fn update_filter_settings(&mut self, severity_filter: Option<String>, status_filter: Option<String>) -> Result<()> {
        self.filter_settings.severity_filter = severity_filter;
        self.filter_settings.status_filter = status_filter;
        self.save().await
    }

    pub async fn save(&self) -> Result<()> {
        let config_path = get_config_path()?;

        // Create directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let content = serde_json::to_string_pretty(self)?;
        tokio::fs::write(config_path, content).await?;
        Ok(())
    }
}

pub async fn init_config() -> Result<()> {
    println!("Setting up XDRTop configuration...");
    
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

    print!("Enter Tenant URL (e.g., https://api-tenant.xdr.au.paloaltonetworks.com): ");
    io::stdout().flush()?;
    let mut tenant_url = String::new();
    io::stdin().read_line(&mut tenant_url)?;
    let tenant_url = tenant_url.trim().to_string();

    let config = Config {
        api_key_id,
        api_key_secret,
        tenant_url,
        filter_settings: FilterSettings::default(),
    };

    config.save().await?;
    println!("Configuration saved successfully!");
    Ok(())
}

fn get_config_path() -> Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow!("Unable to find home directory"))?;
    Ok(home.join(".xdrtop").join("config.json"))
}
