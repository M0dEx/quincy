use crate::auth::token::SessionToken;
use anyhow::{anyhow, Result};
use getset::Getters;

#[derive(Getters)]
pub struct User {
    #[get = "pub"]
    name: String,
    #[get = "pub"]
    password_hash_string: String,
    #[get = "pub"]
    session_token: Option<SessionToken>,
}

impl User {
    pub fn new(name: String, password_hash_string: String) -> Self {
        Self {
            name,
            password_hash_string,
            session_token: None,
        }
    }
}

impl TryFrom<String> for User {
    type Error = anyhow::Error;

    fn try_from(user_string: String) -> Result<Self> {
        let split: Vec<String> = user_string.split(':').map(|str| str.to_owned()).collect();
        let name = split
            .get(0)
            .ok_or_else(|| anyhow!("Failed to parse username from string: {user_string}"))?
            .clone();
        let password_hash_string = split
            .get(0)
            .ok_or_else(|| anyhow!("Failed to parse password hash from string: {user_string}"))?
            .clone();

        Ok(User::new(name, password_hash_string))
    }
}
