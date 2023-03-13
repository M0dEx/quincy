use std::collections::hash_map::Entry;
use std::collections::HashMap;
use anyhow::Result;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use serde::de::DeserializeOwned;
use tracing::warn;

#[derive(Debug, Copy, Clone)]
pub enum Mode {
    Client,
    Server,
}

impl From<String> for Mode {
    fn from(s: String) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "server" => Mode::Server,
            _ => Mode::Client,
        }
    }
}

//
//  SERVER CONFIG
//
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerConfig {
    tunnel_path: Option<PathBuf>,
    pub tunnels: HashMap<String, TunnelConfig>,
    pub connection: ConnectionConfig,
    pub log: LogConfig,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TunnelConfig {
    pub name: String,
    pub certificate_file: PathBuf,
    pub certificate_key_file: PathBuf,
    #[serde(default = "default_bind_address")]
    pub bind_address: Ipv4Addr,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    pub address_server: Ipv4Addr,
    pub address_mask: Ipv4Addr,
}

//
//  CLIENT CONFIG
//
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientConfig {
    pub connection_address: String,
    pub authentication: ClientAuthenticationConfig,
    pub connection: ConnectionConfig,
    pub log: LogConfig,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientAuthenticationConfig {
    pub username: String,
    pub password: String,
    pub trusted_certificates: Vec<PathBuf>,
}

//
//  SHARED CONFIG
//
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    pub mtu: u32,
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u64,
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u64,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

pub trait ConfigInit<T: DeserializeOwned> {
    /// Initializes the configuration object from the given Figment
    ///
    /// * `figment` - The Figment to use for initialization
    fn init(figment: Figment, _env_prefix: &str) -> Result<T> {
        Ok(figment.extract()?)
    }
}

pub trait FromPath<T: DeserializeOwned + ConfigInit<T>> {
    /// Creates a configuration object from the given path and ENV prefix
    ///
    /// * `path` - Path to a configuration file
    /// * `env_prefix` - ENV prefix to use for overrides
    fn from_path(path: &PathBuf, env_prefix: &str) -> Result<T> {
        let figment = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed(env_prefix));

        Ok(T::init(figment, env_prefix)?)
    }
}

impl ConfigInit<ServerConfig> for ServerConfig {
    fn init(figment: Figment, env_prefix: &str) -> Result<ServerConfig> {
        let mut config: ServerConfig = figment.extract()?;

        let tunnel_configs: Vec<TunnelConfig> = match &config.tunnel_path {
            Some(tunnel_path) => {
                if tunnel_path.is_dir() {
                    tunnel_path
                        .read_dir()?
                        .flatten()
                        .filter_map(
                            |config_file| Some(TunnelConfig::from_path(&config_file.path(), env_prefix).ok()?))
                        .collect()
                } else {
                    warn!("Failed to load tunnel configuration files from '{tunnel_path:?}' - the folder does not exist");
                    vec![]
                }
            },
            None => vec![]
        };
        
        for tunnel in tunnel_configs {
            match config.tunnels.entry(tunnel.name.clone()) {
                Entry::Occupied(_) => warn!("Tunnel with the name {} already exists", tunnel.name),
                Entry::Vacant(slot) => {slot.insert(tunnel);},
            }
        }

        Ok(config)
    }
}
impl ConfigInit<ClientConfig> for ClientConfig {}
impl ConfigInit<TunnelConfig> for TunnelConfig {}

impl FromPath<ServerConfig> for ServerConfig {}
impl FromPath<ClientConfig> for ClientConfig {}
impl FromPath<TunnelConfig> for TunnelConfig {}

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
