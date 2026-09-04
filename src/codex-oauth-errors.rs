use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RefreshFailureCode {
    RefreshTokenExpired,
    RefreshTokenReused,
    RefreshTokenInvalidated,
    InvalidRefreshToken,
    InvalidGrant,
    Unauthorized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RefreshFailure {
    status: u16,
    code: RefreshFailureCode,
}

impl RefreshFailure {
    pub(super) fn from_response(status: u16, body: &[u8]) -> Option<Self> {
        let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let code = value
            .pointer("/error/code")
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .or_else(|| value.get("code").and_then(Value::as_str));
        let code = match code.map(str::to_ascii_lowercase).as_deref() {
            Some("refresh_token_expired") => RefreshFailureCode::RefreshTokenExpired,
            Some("refresh_token_reused") => RefreshFailureCode::RefreshTokenReused,
            Some("refresh_token_invalidated") => RefreshFailureCode::RefreshTokenInvalidated,
            Some("invalid_refresh_token") => RefreshFailureCode::InvalidRefreshToken,
            Some("invalid_grant") if status == 400 || status == 401 => {
                RefreshFailureCode::InvalidGrant
            }
            _ if status == 401 => RefreshFailureCode::Unauthorized,
            _ => return None,
        };
        Some(Self { status, code })
    }
}

impl std::fmt::Display for RefreshFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_value(&self.code).map_err(|_| std::fmt::Error)?;
        write!(
            f,
            "Codex OAuth token refresh failed ({}, {}). Reconnect this ChatGPT account.",
            self.status,
            code.as_str().unwrap_or("unauthorized")
        )
    }
}

pub(super) enum RefreshError {
    Permanent(RefreshFailure),
    Transient(String),
}

impl From<String> for RefreshError {
    fn from(error: String) -> Self {
        Self::Transient(error)
    }
}

pub(super) fn check_refresh_failure(value: &Value) -> Result<(), String> {
    if let Some(failure) = value.get("refresh_error") {
        let failure: RefreshFailure = serde_json::from_value(failure.clone())
            .map_err(|_| "Invalid ChatGPT refresh state; reconnect this account".to_string())?;
        return Err(failure.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_refresh_classifies_provider_codes_without_exposing_payloads() {
        for (status, body, expected) in [
            (
                400,
                r#"{"error":"invalid_grant","error_description":"private"}"#,
                Some("invalid_grant"),
            ),
            (
                400,
                r#"{"error":{"code":"refresh_token_expired"}}"#,
                Some("refresh_token_expired"),
            ),
            (
                400,
                r#"{"code":"refresh_token_invalidated"}"#,
                Some("refresh_token_invalidated"),
            ),
            (401, "private upstream response", Some("unauthorized")),
            (429, r#"{"error":"rate_limited"}"#, None),
            (503, r#"{"error":"temporarily_unavailable"}"#, None),
        ] {
            let failure = RefreshFailure::from_response(status, body.as_bytes());
            if let Some(code) = expected {
                let message = failure.unwrap().to_string();
                assert!(message.contains(code));
                assert!(!message.contains("private"));
            } else {
                assert!(failure.is_none());
            }
        }
    }
}
