use crate::constants::CPRNG;
use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use getset::Getters;
use rand_chacha::rand_core::RngCore;

#[derive(Getters)]
pub struct User {
    #[get = "pub"]
    name: String,
    #[get = "pub"]
    password_hash_string: String,
    session_tokens: DashMap<Bytes, DateTime<Utc>>,
}

impl User {
    pub fn new(name: String, password_hash_string: String) -> Self {
        Self {
            name,
            password_hash_string,
            session_tokens: DashMap::new(),
        }
    }

    pub fn check_session_validity(&self, session_token: Bytes) -> bool {
        let valid = match self.session_tokens.get(&session_token) {
            Some(token) => &Utc::now() <= token.value(),
            None => false,
        };

        if !valid {
            self.session_tokens.remove(&session_token);
        }

        valid
    }

    pub async fn new_session(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(32);

        CPRNG.lock().await.fill_bytes(&mut buf);

        let session_token: Bytes = buf.into();

        // TODO: Make this configurable
        self.session_tokens
            .insert(session_token.clone(), Utc::now() + Duration::days(1));

        session_token
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
