pub mod user;

use crate::auth::user::User;
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use bincode::{Decode, Encode};
use bytes::Bytes;
use dashmap::DashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Represents the internal authentication state for a session.
pub enum AuthState {
    Unauthenticated,
    Authenticated(String),
    Failed,
}

/// Represents an authentication message sent by the client.
#[derive(Encode, Decode)]
pub enum AuthClientMessage {
    Authentication(String, String),
    SessionToken(Vec<u8>),
}

/// Represents an authentication message sent by the server.
#[derive(Encode, Decode)]
pub enum AuthServerMessage {
    Authenticated(u32, u32, Vec<u8>),
    Ok,
}

/// Represents a module providing basic authentication functionality.
pub struct Auth {
    users: DashMap<String, User>,
    hasher: Argon2<'static>,
}

impl Auth {
    /// Creates a new instance of the authentication module.
    ///
    /// ### Arguments
    /// - `users` - a map of users (username -> `User`)
    pub fn new(users: DashMap<String, User>) -> Self {
        Self {
            users,
            hasher: Argon2::default(),
        }
    }

    /// Authenticates the given users and returns a session token if successful.
    ///
    /// ### Arguments
    /// - `username` - the username
    /// - `password` - the password
    ///
    /// ### Returns
    /// - `Bytes` containing the session token
    pub async fn authenticate(&self, username: &str, password: String) -> Result<Bytes> {
        let user = self
            .users
            .get(username)
            .ok_or_else(|| anyhow!("Unknown user: {username}"))?;
        let password_hash = PasswordHash::new(user.password_hash()).map_err(|err| {
            anyhow!("Could not parse user password hash for user '{username}': {err}")
        })?;

        self.hasher
            .verify_password(password.as_bytes(), &password_hash)
            .map_err(|err| anyhow!("Could not verify credentials for user '{username}': {err}"))?;

        Ok(user.new_session().await)
    }

    /// Verifies the given session token for the specified user.
    ///
    /// ### Arguments
    /// - `username` - the username
    /// - `session_token` - the session token
    ///
    /// ### Returns
    /// - `true` if the session token is valid, `false` otherwise
    pub fn verify_session_token(&self, username: &str, session_token: Bytes) -> Result<bool> {
        let user = self
            .users
            .get(username)
            .ok_or_else(|| anyhow!("Unknown user: {username}"))?;

        Ok(user.check_session_validity(session_token))
    }

    /// Loads the contents of a file with users and their passwords hashes into a map.
    ///
    /// ### Arguments
    /// - `users_file` - path to the users file
    ///
    /// ### Returns
    /// - `DashMap` containing all loaded users
    pub fn load_users_file(users_file: &Path) -> Result<DashMap<String, User>> {
        let file = File::open(users_file)?;
        let lines = BufReader::new(file).lines();

        let result: DashMap<String, User> = DashMap::new();

        for line in lines {
            let user: User = line?.try_into()?;
            result.insert(user.username().clone(), user);
        }

        Ok(result)
    }
}
