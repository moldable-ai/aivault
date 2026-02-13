use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    pub secret_id: String,
}

impl SecretRef {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let Some(rest) = trimmed.strip_prefix("vault:secret:") else {
            return Err("invalid secret_ref (expected vault:secret:<id>)".to_string());
        };
        let id = rest.trim();
        if id.is_empty() {
            return Err("invalid secret_ref (missing id)".to_string());
        }
        Ok(Self {
            secret_id: id.to_string(),
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vault:secret:{}", self.secret_id)
    }
}
