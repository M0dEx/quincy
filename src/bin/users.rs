use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use clap::Parser;
use quincy::auth::user::User;
use quincy::auth::Auth;
use rpassword::prompt_password;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "quincy")]
pub struct Args {
    #[arg()]
    pub users_file_path: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut username = String::new();
    print!("Enter the username: ");
    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut username)?;
    username = username.trim_end().to_owned();

    let password = prompt_password(format!("Enter password for user '{username}': "))?;
    let password_again = prompt_password(format!("Confirm password for user '{username}': "))?;

    if password != password_again {
        eprintln!("Passwords do not match");
        return Ok(());
    }

    let users = Auth::load_users_file(&args.users_file_path)?;

    let argon = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);

    let password_hash = argon
        .hash_password(password.as_bytes(), salt.as_salt())
        .map_err(|e| anyhow!("Failed to hash password: {e}"))?;

    users.insert(
        username.clone(),
        User::new(username, password_hash.to_string()),
    );

    Auth::save_users_file(&args.users_file_path, users)?;

    Ok(())
}
