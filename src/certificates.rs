use anyhow::anyhow;
use anyhow::Result;
use rustls::{Certificate, PrivateKey};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use tokio::task;

fn load_certificates_bytes_from_file(path: PathBuf) -> Result<Vec<Vec<u8>>> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);

    let certificates_bytes = rustls_pemfile::certs(&mut reader)?;

    Ok(certificates_bytes)
}

fn load_private_key_bytes_from_file(path: PathBuf) -> Result<Vec<u8>> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);

    let private_key_bytes = rustls_pemfile::pkcs8_private_keys(&mut reader)?
        .get(0)
        .ok_or_else(|| anyhow!("No private key found in the file: {path:?}"))?
        .clone();

    Ok(private_key_bytes)
}

pub async fn load_certificates_from_file(path: PathBuf) -> Result<Vec<Certificate>> {
    let certificates_bytes =
        task::spawn_blocking(|| load_certificates_bytes_from_file(path)).await??;

    Ok(certificates_bytes
        .into_iter()
        .map(|certificate_bytes| Certificate(certificate_bytes))
        .collect())
}

pub async fn load_private_key_from_file(path: PathBuf) -> Result<PrivateKey> {
    let private_key_bytes =
        task::spawn_blocking(|| load_private_key_bytes_from_file(path)).await??;

    Ok(PrivateKey(private_key_bytes))
}
