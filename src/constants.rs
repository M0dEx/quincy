use std::sync::{Arc, LazyLock};

use quinn::Runtime;
use rustls::crypto::CryptoProvider;
use rustls::{CipherSuite, SupportedCipherSuite};

/// Represents the maximum MTU overhead for QUIC, since the QUIC header is variable in size.
pub const QUIC_MTU_OVERHEAD: u16 = 50;

/// Buffer size for authentication messages.
pub const AUTH_MESSAGE_BUFFER_SIZE: usize = 1024;

/// Packet buffer size for operations on the TUN interface.
pub const PACKET_BUFFER_SIZE: usize = 4;

/// Packet channel size used for communication between the TUN interface and QUIC tunnels.
pub const PACKET_CHANNEL_SIZE: usize = 1024 * 1024;

/// Represents the supported TLS protocol versions for Quincy.
pub static TLS_PROTOCOL_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// Represents the supported TLS ALPN protocols for Quincy.
pub static TLS_ALPN_PROTOCOLS: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| vec![b"quincy".to_vec()]);

/// Represents the default cipher suite used for initial packets.
pub static TLS_INITIAL_CIPHER_SUITE: LazyLock<SupportedCipherSuite> = LazyLock::new(|| {
    #[cfg(all(feature = "crypto-standard", not(feature = "crypto-quantum")))]
    return rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    #[cfg(all(feature = "crypto-quantum", not(feature = "crypto-standard")))]
    return rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
});

/// Represents the async runtime used by Quinn.
pub static QUINN_RUNTIME: LazyLock<Arc<dyn Runtime>> =
    LazyLock::new(|| Arc::new(quinn::TokioRuntime));

/// Represents the crypto provider used by Quincy.
pub static CRYPTO_PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| {
    #[cfg(all(feature = "crypto-standard", not(feature = "crypto-quantum")))]
    let mut default_provider = {
        use rustls::crypto::ring;
        ring::default_provider()
    };
    #[cfg(all(feature = "crypto-quantum", not(feature = "crypto-standard")))]
    let mut default_provider = {
        use rustls::crypto::aws_lc_rs;
        aws_lc_rs::default_provider()
    };

    // Only support the most secure cipher suites from TLS 1.3
    default_provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384 | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });

    #[cfg(all(feature = "crypto-standard", not(feature = "crypto-quantum")))]
    let provider = default_provider;

    #[cfg(all(feature = "crypto-quantum", not(feature = "crypto-standard")))]
    let provider = {
        use rustls_post_quantum::X25519Kyber768Draft00;

        // Use the post-quantum-secure KX algorithm
        CryptoProvider {
            kx_groups: vec![&X25519Kyber768Draft00],
            ..default_provider
        }
    };

    Arc::new(provider)
});
