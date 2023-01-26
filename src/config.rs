use anyhow::{anyhow, Result};
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Debug, Copy, Clone)]
pub enum Mode {
    CLIENT,
    SERVER,
}

impl From<String> for Mode {
    fn from(s: String) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "server" => Mode::SERVER,
            _ => Mode::CLIENT,
        }
    }
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    pub client: Option<ClientConfig>,
    pub server: Option<ServerConfig>,
    pub connection: ConnectionConfig,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ClientConfig {
    pub username: String,
    pub password: String,
    pub connection_address: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ServerConfig {
    pub certificate_file: PathBuf,
    pub certificate_key_file: PathBuf,
    #[serde(default = "default_bind_address")]
    pub bind_address: Ipv4Addr,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    pub address_server: Ipv4Addr,
    pub address_mask: Ipv4Addr,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    pub mtu: u32,
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u64,
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u64,
}

impl Config {
    /// Creates a configuration object from the given path and ENV prefix
    ///
    /// * `path` - Path to a configuration file
    /// * `env_prefix` - ENV prefix to use for overrides
    /// * `mode` - The Mode currently being used
    pub fn from_path(path: &PathBuf, env_prefix: &String, mode: Mode) -> Result<Self> {
        let figment = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed(&env_prefix));

        let config: Config = figment.extract()?;

        let valid = match mode {
            Mode::CLIENT => config.client.is_some(),
            Mode::SERVER => config.server.is_some(),
        };

        if !valid {
            return Err(anyhow!(
                "The configuration section for the given mode '{:?}' is missing",
                mode
            ));
        }

        Ok(config)
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_bind_address() -> Ipv4Addr {
    "0.0.0.0".parse().expect("Default address is valid")
}

fn default_bind_port() -> u16 {
    55555
}

fn default_buffer_size() -> u64 {
    2097152
}
