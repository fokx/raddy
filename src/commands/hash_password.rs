use anyhow::{Context, Result, bail};
use std::io::{self, Read};

/// Executes `raddy hash-password` command.
pub fn hash_password_command(
    plaintext: Option<String>,
    algorithm: Option<&str>,
    cost: Option<u32>,
) -> Result<()> {
    let algo = algorithm.unwrap_or("bcrypt");
    if algo != "bcrypt" {
        bail!(
            "Unsupported algorithm '{}'. Only 'bcrypt' is currently supported.",
            algo
        );
    }

    let password = match plaintext {
        Some(p) => p,
        None => {
            // Read from stdin
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read password from stdin")?;
            buffer.trim_end_matches(&['\r', '\n'][..]).to_string()
        }
    };

    if password.is_empty() {
        bail!("Password cannot be empty");
    }

    let bcrypt_cost = cost.unwrap_or(bcrypt::DEFAULT_COST);
    let hash =
        bcrypt::hash(password, bcrypt_cost).context("Failed to hash password with bcrypt")?;

    println!("{}", hash);
    Ok(())
}
