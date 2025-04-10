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

