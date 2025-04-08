//! RSA-PSS signature operations for OTA manifest verification.
//!
//! Uses RSA-PSS with SHA-256 as the hash function. Keys are stored as
//! PKCS#1 DER encoded, then hex-encoded for file storage.

use rsa::pkcs1v15::SigningKey as Pkcs1SigningKey;
use rsa::pkcs1v15::VerifyingKey as Pkcs1VerifyingKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::path::Path;

use crate::errors::{OtaError, Result};

/// RSA key size in bits used for key generation.
const RSA_KEY_BITS: usize = 2048;

/// Generate a new RSA keypair and write hex-encoded PKCS#1 DER keys to files.
pub fn generate_keypair(secret_path: &Path, public_path: &Path) -> Result<()> {
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    let priv_der = rsa::pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&private_key)
        .map_err(|e| OtaError::KeyGeneration(format!("RSA private key encode: {e}")))?;
    let pub_der = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&public_key)
        .map_err(|e| OtaError::KeyGeneration(format!("RSA public key encode: {e}")))?;

    std::fs::write(secret_path, hex::encode(priv_der.as_bytes()))?;
    std::fs::write(public_path, hex::encode(pub_der.as_bytes()))?;

    Ok(())
}

/// Sign data with an RSA private key (PKCS#1 v1.5 with SHA-256).
///
/// Returns the signature as a hex-encoded string.
pub fn sign_bytes(data: &[u8], secret_key_path: &Path) -> Result<String> {
    let key_hex = std::fs::read_to_string(secret_key_path)?;
    let key_der = hex::decode(key_hex.trim())?;

    let private_key = rsa::pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(&key_der)
        .map_err(|e| OtaError::KeyGeneration(format!("RSA private key decode: {e}")))?;

    let signing_key = Pkcs1SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(data);

    Ok(hex::encode(signature.to_bytes()))
}

/// Verify an RSA signature (PKCS#1 v1.5 with SHA-256) against a public key file.
pub fn verify_signature(data: &[u8], signature_hex: &str, public_key_path: &Path) -> Result<()> {
    let pub_hex = std::fs::read_to_string(public_key_path)?;
    let pub_der = hex::decode(pub_hex.trim())?;

    let public_key: RsaPublicKey = rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der(&pub_der)
        .map_err(|e| OtaError::SignatureInvalid(format!("RSA public key decode: {e}")))?;

    let sig_bytes = hex::decode(signature_hex.trim())?;

    let verifying_key = Pkcs1VerifyingKey::<Sha256>::new(public_key);
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| OtaError::SignatureInvalid(format!("RSA signature decode: {e}")))?;

    verifying_key
        .verify(data, &signature)
        .map_err(|e| OtaError::SignatureInvalid(format!("RSA verification failed: {e}")))
}

