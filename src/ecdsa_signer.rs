//! ECDSA P-256 signature operations for OTA manifest verification.
//!
//! Uses ECDSA with the NIST P-256 curve and SHA-256 digest.
//! Keys are stored as SEC1 (private) / compressed point (public), hex-encoded.

use ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use std::path::Path;

use crate::errors::{OtaError, Result};

/// Generate a new ECDSA P-256 keypair and write hex-encoded keys to files.
///
/// Private key: 32 bytes (SEC1 scalar), hex-encoded.
/// Public key: 33 bytes (SEC1 compressed point), hex-encoded.
pub fn generate_keypair(secret_path: &Path, public_path: &Path) -> Result<()> {
    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let secret_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_encoded_point(true);

    std::fs::write(secret_path, hex::encode(secret_bytes.as_slice()))?;
    std::fs::write(public_path, hex::encode(public_bytes.as_bytes()))?;

    Ok(())
}

/// Sign data with an ECDSA P-256 private key.
///
/// Returns the signature as a hex-encoded DER string.
pub fn sign_bytes(data: &[u8], secret_key_path: &Path) -> Result<String> {
    let key_hex = std::fs::read_to_string(secret_key_path)?;
    let key_bytes = hex::decode(key_hex.trim())?;

    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| OtaError::KeyGeneration(format!("ECDSA private key decode: {e}")))?;

    let signature: Signature = signing_key.sign(data);

    Ok(hex::encode(signature.to_bytes()))
}

/// Verify an ECDSA P-256 signature against a public key file.
pub fn verify_signature(data: &[u8], signature_hex: &str, public_key_path: &Path) -> Result<()> {
    let pub_hex = std::fs::read_to_string(public_key_path)?;
    let pub_bytes = hex::decode(pub_hex.trim())?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| OtaError::SignatureInvalid(format!("ECDSA public key decode: {e}")))?;

    let sig_bytes = hex::decode(signature_hex.trim())?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| OtaError::SignatureInvalid(format!("ECDSA signature decode: {e}")))?;

    verifying_key
        .verify(data, &signature)
        .map_err(|e| OtaError::SignatureInvalid(format!("ECDSA verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn gen_temp_keypair() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempdir().expect("tmpdir");
        let secret = dir.path().join("ecdsa-secret.key");
        let public = dir.path().join("ecdsa-public.key");
        generate_keypair(&secret, &public).expect("ecdsa keygen");
        (dir, secret, public)
    }

    #[test]
    fn ecdsa_keygen_produces_valid_files() {
        let (_dir, secret_path, public_path) = gen_temp_keypair();

        let secret_hex = std::fs::read_to_string(&secret_path).unwrap();
        let public_hex = std::fs::read_to_string(&public_path).unwrap();

        // P-256 private key is 32 bytes = 64 hex chars
        assert_eq!(secret_hex.len(), 64);
        // Compressed public key is 33 bytes = 66 hex chars
        assert_eq!(public_hex.len(), 66);
        assert!(hex::decode(&secret_hex).is_ok());
        assert!(hex::decode(&public_hex).is_ok());
    }

    #[test]
    fn ecdsa_sign_then_verify_succeeds() {
        let (_dir, secret_path, public_path) = gen_temp_keypair();

        let data = b"firmware payload ecdsa test";
        let sig_hex = sign_bytes(data, &secret_path).expect("ecdsa sign");

        verify_signature(data, &sig_hex, &public_path).expect("ecdsa verify should succeed");
    }

    #[test]
    fn ecdsa_verify_with_wrong_key_fails() {
        let (_dir1, secret_path, _pub1) = gen_temp_keypair();
        let (_dir2, _sec2, public_path2) = gen_temp_keypair();

        let data = b"firmware payload ecdsa test";
        let sig_hex = sign_bytes(data, &secret_path).expect("ecdsa sign");

        let result = verify_signature(data, &sig_hex, &public_path2);
        assert!(result.is_err());
    }

    #[test]
    fn ecdsa_verify_with_tampered_data_fails() {
        let (_dir, secret_path, public_path) = gen_temp_keypair();

        let data = b"firmware payload ecdsa test";
        let sig_hex = sign_bytes(data, &secret_path).expect("ecdsa sign");

        let tampered = b"firmware payload ecdsa TAMPERED";
        let result = verify_signature(tampered, &sig_hex, &public_path);
        assert!(result.is_err());
    }
}
