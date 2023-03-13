use anyhow::anyhow;
use anyhow::Result;
use rustls::{Certificate, PrivateKey};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub fn load_certificates_from_file(path: &Path) -> Result<Vec<Certificate>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let certificates_bytes = rustls_pemfile::certs(&mut reader)?;

    Ok(certificates_bytes.into_iter().map(Certificate).collect())
}

pub fn load_private_key_from_file(path: &Path) -> Result<PrivateKey> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);

    let private_key_bytes = rustls_pemfile::pkcs8_private_keys(&mut reader)?
        .get(0)
        .ok_or_else(|| anyhow!("No private key found in the file: {path:?}"))?
        .clone();

    Ok(PrivateKey(private_key_bytes))
}
