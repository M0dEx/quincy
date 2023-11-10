use anyhow::anyhow;
use anyhow::Result;
use rustls::{Certificate, PrivateKey};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Loads certificates from a file.
///
/// ### Arguments
/// - `path` - Path to the file containing the certificates.
///
/// ### Returns
/// - `Vec<Certificate>` - A list of loaded certificates.
pub fn load_certificates_from_file(path: &Path) -> Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let certificates_bytes = rustls_pemfile::certs(&mut reader)?;

    Ok(certificates_bytes.into_iter().map(Certificate).collect())
}

/// Loads a private key from a file.
///
/// ### Arguments
/// - `path` - Path to the file containing the private key.
///
/// ### Returns
/// - `PrivateKey` - The loaded private key.
pub fn load_private_key_from_file(path: &Path) -> Result<PrivateKey> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let private_key_bytes = rustls_pemfile::pkcs8_private_keys(&mut reader)?
        .first()
        .ok_or_else(|| anyhow!("No private key found in the file: {path:?}"))?
        .clone();

    Ok(PrivateKey(private_key_bytes))
}
