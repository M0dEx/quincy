use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use figment::{Figment, providers::{Format, Toml, Env}};
use serde::Deserialize;

#[derive(Copy, Clone)]
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
    pub certificates_file: PathBuf,
    pub certificate_key_file: PathBuf,
    #[serde(default = "default_bind_address")]
    pub bind_address: Ipv4Addr,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    pub dhcp: DHCPConfig,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    pub mtu: u16,
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u64,
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u64,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct DHCPConfig {
    pub address_server: Ipv4Addr,
    pub address_range_start: Ipv4Addr,
    pub address_range_end: Ipv4Addr,
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
            Mode::CLIENT => config.client.is_some() && config.server.is_none(),
            Mode::SERVER => config.server.is_some() && config.client.is_none()
        };

        if !valid {
            return Err(anyhow!("Only one section (config/server) in the configuration file might be configured at once."))
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