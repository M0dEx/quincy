use anyhow::Result;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    EndpointConfig, TransportConfig,
};
use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::certificates::{load_certificates_from_file, load_private_key_from_file};
use crate::constants::{
    CRYPTO_PROVIDER, QUIC_MTU_OVERHEAD, TLS_ALPN_PROTOCOLS, TLS_PROTOCOL_VERSIONS,
};
use tracing::error;

/// Represents the configuration for a Quincy server.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerConfig {
    /// The name of the tunnel
    pub name: String,
    /// The certificate to use for the tunnel
    pub certificate_file: PathBuf,
    /// The certificate private key to use for the tunnel
    pub certificate_key_file: PathBuf,
    /// The address to bind the tunnel to (default = 0.0.0.0)
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    /// The port to bind the tunnel to (default = 55555)
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    /// Whether to reuse the socket (default = false)
    ///
    /// This is useful when running multiple Quincy instances on the same port for load balancing.
    ///
    /// Unsupported on Windows.
    #[serde(default = "default_false_fn")]
    pub reuse_socket: bool,
    /// The address of this tunnel
    pub address_tunnel: Ipv4Addr,
    /// The address mask for this tunnel
    pub address_mask: Ipv4Addr,
    /// Whether to isolate clients from each other (default = true)
    #[serde(default = "default_true_fn")]
    pub isolate_clients: bool,
    /// Authentication configuration
    pub authentication: ServerAuthenticationConfig,
    /// Miscellaneous connection configuration
    pub connection: ConnectionConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Represents the configuration for a Quincy server's authentication.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ServerAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The path to the file containing the list of users and their password hashes
    pub users_file: PathBuf,
}

/// Represents the configuration for a Quincy client.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientConfig {
    /// Connection string to be used to connect to a Quincy server
    pub connection_string: String,
    /// Authentication configuration
    pub authentication: ClientAuthenticationConfig,
    /// Miscellaneous connection configuration
    pub connection: ConnectionConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Represents the configuration for a Quincy client's authentication.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ClientAuthenticationConfig {
    /// The type of authenticator to use (default = users_file)
    #[serde(default = "default_auth_type")]
    pub auth_type: AuthType,
    /// The username to use for authentication
    pub username: String,
    /// The password to use for authentication
    pub password: String,
    /// A list of trusted certificates
    pub trusted_certificates: Vec<PathBuf>,
}

/// Represents miscellaneous connection configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ConnectionConfig {
    /// The MTU to use for connections and the TUN interface (default = 1400)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// The time after which a connection is considered timed out (default = 30s)
    #[serde(default = "default_timeout")]
    pub connection_timeout: Duration,
    /// Keep alive interval for connections (default = 25s)
    #[serde(default = "default_keep_alive_interval")]
    pub keep_alive_interval: Duration,
    /// The size of the send buffer of the socket and Quinn endpoint (default = 2097152)
    #[serde(default = "default_buffer_size")]
    pub send_buffer_size: u64,
    /// The size of the receive buffer of the socket and Quinn endpoint (default = 2097152)
    #[serde(default = "default_buffer_size")]
    pub recv_buffer_size: u64,
}

/// Represents logging configuration.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct LogConfig {
    /// The log level to use (default = info)
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub enum AuthType {
    UsersFile,
}

pub trait ConfigInit<T: DeserializeOwned> {
    /// Initializes the configuration object from the given Figment
    ///
    /// ### Arguments
    /// - `figment` - the Figment to use for initialization
    fn init(figment: Figment, _env_prefix: &str) -> Result<T> {
        Ok(figment.extract()?)
    }
}

pub trait FromPath<T: DeserializeOwned + ConfigInit<T>> {
    /// Creates a configuration object from the given path and ENV prefix
    ///
    /// ### Arguments
    /// - `path` - a path to the configuration file
    /// - `env_prefix` - the ENV prefix to use for overrides
    fn from_path(path: &Path, env_prefix: &str) -> Result<T> {
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "configuration file {path:?} does not exist or cannot be read"
            ));
        }

        let figment = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed(env_prefix));

        T::init(figment, env_prefix)
    }
}

impl ConfigInit<ServerConfig> for ServerConfig {}
impl ConfigInit<ClientConfig> for ClientConfig {}

impl FromPath<ServerConfig> for ServerConfig {}
impl FromPath<ClientConfig> for ClientConfig {}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_bind_address() -> IpAddr {
    "0.0.0.0".parse().expect("Default address is valid")
}

fn default_bind_port() -> u16 {
    55555
}

fn default_buffer_size() -> u64 {
    2097152
}

fn default_mtu() -> u16 {
    1400
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_keep_alive_interval() -> Duration {
    Duration::from_secs(25)
}

fn default_auth_type() -> AuthType {
    AuthType::UsersFile
}

fn default_true_fn() -> bool {
    true
}

fn default_false_fn() -> bool {
    false
}

impl ClientConfig {
    /// Creates Quinn client configuration from this Quincy client configuration.
    ///
    /// ### Returns
    /// - `quinn::ClientConfig` - the Quinn client configuration
    pub fn as_quinn_client_config(&self) -> Result<quinn::ClientConfig> {
        let trusted_certificates: Vec<CertificateDer> = self
            .authentication
            .trusted_certificates
            .iter()
            .filter_map(|cert_path| match load_certificates_from_file(cert_path) {
                Ok(certificates) => Some(certificates),
                Err(e) => {
                    error!("Could not load certificates from {cert_path:?} due to an error: {e}");
                    None
                }
            })
            .flatten()
            .collect();

        let mut cert_store = RootCertStore::empty();

        for certificate in trusted_certificates {
            cert_store.add(certificate)?;
        }

        let mut rustls_config =
            rustls::ClientConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
                .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
                .with_root_certificates(cert_store)
                .with_no_client_auth();

        rustls_config.alpn_protocols.clone_from(&TLS_ALPN_PROTOCOLS);

        let quic_client_config = QuicClientConfig::with_initial(
            rustls_config.into(),
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .expect("QUIC initial suite is a valid TLS 1.3 suite")
                .quic_suite()
                .expect("QUIC initial suite is a valid QUIC suite"),
        )?;

        let mut quinn_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        let mut transport_config = TransportConfig::default();

        transport_config.max_idle_timeout(Some(self.connection.connection_timeout.try_into()?));
        transport_config.keep_alive_interval(Some(self.connection.keep_alive_interval));
        transport_config.initial_mtu(self.connection.mtu_with_overhead());
        transport_config.min_mtu(self.connection.mtu_with_overhead());

        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }
}

impl ServerConfig {
    /// Creates Quinn server configuration from this Quincy tunnel configuration.
    ///
    /// ### Arguments
    /// - `connection_config` - the connection configuration to use
    ///
    /// ### Returns
    /// - `quinn::ServerConfig` - the Quinn server configuration
    pub fn as_quinn_server_config(&self) -> Result<quinn::ServerConfig> {
        let certificate_file_path = self.certificate_file.clone();
        let certificate_key_path = self.certificate_key_file.clone();
        let key = load_private_key_from_file(&certificate_key_path)?;
        let certs = load_certificates_from_file(&certificate_file_path)?;

        let mut rustls_config =
            rustls::ServerConfig::builder_with_provider(CRYPTO_PROVIDER.clone())
                .with_protocol_versions(TLS_PROTOCOL_VERSIONS)?
                .with_no_client_auth()
                .with_single_cert(certs, key.into())?;

        rustls_config.alpn_protocols.clone_from(&TLS_ALPN_PROTOCOLS);
        rustls_config.max_early_data_size = 0;

        let quic_server_config = QuicServerConfig::with_initial(
            rustls_config.into(),
            TLS13_AES_128_GCM_SHA256
                .tls13()
                .expect("QUIC initial suite is a valid TLS 1.3 suite")
                .quic_suite()
                .expect("QUIC initial suite is a valid QUIC suite"),
        )?;

        let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let mut transport_config = TransportConfig::default();

        transport_config.max_idle_timeout(Some(self.connection.connection_timeout.try_into()?));
        transport_config.initial_mtu(self.connection.mtu_with_overhead());
        transport_config.min_mtu(self.connection.mtu_with_overhead());

        quinn_config.transport_config(Arc::new(transport_config));

        Ok(quinn_config)
    }
}

impl ConnectionConfig {
    pub fn as_endpoint_config(&self) -> Result<EndpointConfig> {
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.max_udp_payload_size(self.mtu_with_overhead())?;

        Ok(endpoint_config)
    }

    pub fn mtu_with_overhead(&self) -> u16 {
        self.mtu + QUIC_MTU_OVERHEAD
    }
}
