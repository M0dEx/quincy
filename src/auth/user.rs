use std::{
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use dashmap::DashMap;

/// Represents a Quincy user
pub struct User {
    pub username: String,
    pub password_hash: String,
}

impl User {
    /// Creates a new `User` instance given the username and password hash.
    ///
    /// ### Arguments
    /// - `username` - the username
    /// - `password_hash` - a password hash representing the user's password
    pub fn new(username: String, password_hash: String) -> Self {
        Self {
            username,
            password_hash,
        }
    }
}

impl TryFrom<String> for User {
    type Error = anyhow::Error;

    fn try_from(user_string: String) -> Result<Self> {
        let split: Vec<String> = user_string.split(':').map(|str| str.to_owned()).collect();
        let name = split
            .first()
            .ok_or_else(|| anyhow!("Failed to parse username from string: {user_string}"))?
            .clone();
        let password_hash_string = split
            .get(1)
            .ok_or_else(|| anyhow!("Failed to parse password hash from string: {user_string}"))?
            .clone();

        Ok(User::new(name, password_hash_string))
    }
}

/// Represents a user database
pub struct UserDatabase {
    users: DashMap<String, User>,
    hasher: Argon2<'static>,
}

impl UserDatabase {
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
    pub async fn authenticate(&self, username: &str, password: String) -> Result<()> {
        let user = self
            .users
            .get(username)
            .ok_or_else(|| anyhow!("Unknown user: {username}"))?;
        let password_hash = PasswordHash::new(&user.password_hash).map_err(|err| {
            anyhow!("Could not parse user password hash for user '{username}': {err}")
        })?;

        self.hasher
            .verify_password(password.as_bytes(), &password_hash)
            .map_err(|err| anyhow!("Failed to verify password for user {username}: {err}"))?;

        Ok(())
    }
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
        result.insert(user.username.clone(), user);
    }

    Ok(result)
}

/// Writes the users and their password hashes into the specified file
///
/// ### Arguments
/// - `users_file` - path to the users file
/// - `users` - a map of users (username -> `User`)
pub fn save_users_file(users_file: &Path, users: DashMap<String, User>) -> Result<()> {
    if users_file.exists() {
        fs::remove_file(users_file)?;
    }

    let file = File::create(users_file)?;
    let mut writer = BufWriter::new(file);

    for (username, user) in users {
        writer.write_all(format!("{username}:{}\n", user.password_hash).as_bytes())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::auth::user::{User, UserDatabase};
    use argon2::password_hash::rand_core::OsRng;
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    use dashmap::DashMap;

    #[tokio::test]
    async fn test_authentication() {
        let users: DashMap<String, User> = DashMap::new();

        let argon = Argon2::default();
        let username = "test".to_owned();
        let password = "password".to_owned();
        let salt = SaltString::generate(&mut OsRng);

        let password_hash = argon.hash_password(password.as_bytes(), &salt).unwrap();

        let test_user = User::new(username.clone(), password_hash.to_string());
        users.insert(username.clone(), test_user);

        let user_db = UserDatabase::new(users);
        user_db
            .authenticate(&username, password)
            .await
            .expect("Credentials are valid");
    }
}
