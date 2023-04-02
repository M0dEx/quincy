pub mod user;

use crate::auth::user::User;
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use bytes::Bytes;
use dashmap::DashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub struct Auth {
    users: DashMap<String, User>,
    hasher: Argon2<'static>,
}

impl Auth {
    pub fn new(users_file: &Path) -> Result<Self> {
        Ok(Self {
            users: Auth::load_users_file(users_file)?,
            hasher: Argon2::default(),
        })
    }

    pub async fn verify_credentials(&self, username: String, password: String) -> Result<Bytes> {
        let user = self
            .users
            .get(&username)
            .ok_or_else(|| anyhow!("Unknown user: {username}"))?;
        let password_hash = PasswordHash::new(user.password_hash_string()).map_err(|err| {
            anyhow!("Could not parse user password hash for user '{username}': {err}")
        })?;

        self.hasher
            .verify_password(password.as_bytes(), &password_hash)
            .map_err(|err| anyhow!("Could not verify credentials for user '{username}': {err}"))?;

        Ok(user.new_session().await)
    }

    fn load_users_file(users_file: &Path) -> Result<DashMap<String, User>> {
        let file = File::open(users_file)?;
        let lines = BufReader::new(file).lines();

        let result: DashMap<String, User> = DashMap::new();

        for line in lines {
            let user: User = line?.try_into()?;
            result.insert(user.name().clone(), user);
        }

        Ok(result)
    }
}
