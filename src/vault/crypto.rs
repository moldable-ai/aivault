use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PassphraseKdfConfig {
    pub salt_b64: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl PassphraseKdfConfig {
    pub fn new_random_default() -> Self {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        Self {
            salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
            // Conservative defaults for local machines.
            m_cost_kib: 64 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

pub fn random_key_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn derive_kek_from_passphrase(
    passphrase: &str,
    kdf: &PassphraseKdfConfig,
) -> Result<[u8; 32], String> {
    let salt = base64::engine::general_purpose::STANDARD
        .decode(kdf.salt_b64.as_bytes())
        .map_err(|_| "invalid kdf salt".to_string())?;

    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| format!("invalid argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut out)
        .map_err(|e| format!("argon2 error: {}", e))?;
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AeadBlob {
    pub alg: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn aead_encrypt_xchacha20poly1305(
    key_32: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AeadBlob, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_32));
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_obj = XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            nonce_obj,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "encrypt failed".to_string())?;
    Ok(AeadBlob {
        alg: "xchacha20poly1305".to_string(),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
}

pub fn aead_decrypt_xchacha20poly1305(
    key_32: &[u8; 32],
    blob: &AeadBlob,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if blob.alg != "xchacha20poly1305" {
        return Err("unsupported aead alg".to_string());
    }
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(blob.nonce_b64.as_bytes())
        .map_err(|_| "invalid nonce".to_string())?;
    if nonce.len() != 24 {
        return Err("invalid nonce length".to_string());
    }
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(blob.ciphertext_b64.as_bytes())
        .map_err(|_| "invalid ciphertext".to_string())?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_32));
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| "decrypt failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_kek_from_passphrase_is_deterministic_for_same_inputs() {
        let kdf = PassphraseKdfConfig {
            salt_b64: base64::engine::general_purpose::STANDARD.encode("0123456789abcdef"),
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 1,
        };
        let a = derive_kek_from_passphrase("secret-passphrase", &kdf).unwrap();
        let b = derive_kek_from_passphrase("secret-passphrase", &kdf).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_kek_from_passphrase_changes_when_salt_changes() {
        let kdf_a = PassphraseKdfConfig {
            salt_b64: base64::engine::general_purpose::STANDARD.encode("0123456789abcdef"),
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 1,
        };
        let kdf_b = PassphraseKdfConfig {
            salt_b64: base64::engine::general_purpose::STANDARD.encode("fedcba9876543210"),
            m_cost_kib: 8 * 1024,
            t_cost: 2,
            p_cost: 1,
        };
        let a = derive_kek_from_passphrase("secret-passphrase", &kdf_a).unwrap();
        let b = derive_kek_from_passphrase("secret-passphrase", &kdf_b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn aead_rejects_tampered_ciphertext_or_aad() {
        let key = random_key_32();
        let aad = b"vault:aad";
        let blob = aead_encrypt_xchacha20poly1305(&key, b"plaintext", aad).unwrap();

        let mut tampered = blob.clone();
        tampered.ciphertext_b64.push('A');
        assert!(aead_decrypt_xchacha20poly1305(&key, &tampered, aad).is_err());

        assert!(aead_decrypt_xchacha20poly1305(&key, &blob, b"vault:other-aad").is_err());
    }
}
