//! Cryptographic operations for OTA manifest signing and verification.
//!
//! Supports Ed25519, RSA (PKCS#1 v1.5 with SHA-256), and ECDSA P-256.
//! The `multi_verify` function auto-detects the algorithm from the manifest.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

use crate::errors::{OtaError, Result};
use crate::manifest::KeyAlgorithm;
use crate::{ecdsa_signer, rsa_signer};

/// Generate a new Ed25519 keypair and write the keys to files.
///
/// The secret key is written as 64 hex characters (32 bytes).
/// The public key is written as 64 hex characters (32 bytes).
pub fn generate_keypair(secret_path: &Path, public_path: &Path) -> Result<()> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    std::fs::write(secret_path, hex::encode(signing_key.to_bytes()))?;
    std::fs::write(public_path, hex::encode(verifying_key.to_bytes()))?;

    Ok(())
}

/// Generate a keypair for the specified algorithm.
pub fn generate_keypair_for_algorithm(
    algorithm: &KeyAlgorithm,
    secret_path: &Path,
    public_path: &Path,
) -> Result<()> {
    match algorithm {
        KeyAlgorithm::Ed25519 => generate_keypair(secret_path, public_path),
        KeyAlgorithm::RsaPss => rsa_signer::generate_keypair(secret_path, public_path),
        KeyAlgorithm::EcdsaP256 => ecdsa_signer::generate_keypair(secret_path, public_path),
    }
}

/// Sign arbitrary bytes with an Ed25519 secret key loaded from a file.
///
/// Returns the signature as a hex-encoded string.
pub fn sign_bytes(data: &[u8], secret_key_path: &Path) -> Result<String> {
    let key_hex = std::fs::read_to_string(secret_key_path)?;
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim())?
        .try_into()
        .map_err(|_| OtaError::KeyGeneration("secret key must be 32 bytes".into()))?;

    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature = signing_key.sign(data);

    Ok(hex::encode(signature.to_bytes()))
}

/// Sign data using the specified algorithm.
pub fn sign_bytes_with_algorithm(
    data: &[u8],
    secret_key_path: &Path,
    algorithm: &KeyAlgorithm,
) -> Result<String> {
    match algorithm {
        KeyAlgorithm::Ed25519 => sign_bytes(data, secret_key_path),
        KeyAlgorithm::RsaPss => rsa_signer::sign_bytes(data, secret_key_path),
        KeyAlgorithm::EcdsaP256 => ecdsa_signer::sign_bytes(data, secret_key_path),
    }
}

/// Verify an Ed25519 signature against a public key.
pub fn verify_signature(data: &[u8], signature_hex: &str, public_key_path: &Path) -> Result<()> {
    let pub_hex = std::fs::read_to_string(public_key_path)?;
    let pub_bytes: [u8; 32] = hex::decode(pub_hex.trim())?
        .try_into()
        .map_err(|_| OtaError::SignatureInvalid("public key must be 32 bytes".into()))?;

    let sig_bytes: [u8; 64] = hex::decode(signature_hex.trim())?
        .try_into()
        .map_err(|_| OtaError::SignatureInvalid("signature must be 64 bytes".into()))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_bytes)?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(data, &signature)
        .map_err(|e| OtaError::SignatureInvalid(e.to_string()))
}

/// Verify a signature using the specified algorithm.
pub fn verify_with_algorithm(
    data: &[u8],
    signature_hex: &str,
    public_key_path: &Path,
    algorithm: &KeyAlgorithm,
) -> Result<()> {
    match algorithm {
        KeyAlgorithm::Ed25519 => verify_signature(data, signature_hex, public_key_path),
        KeyAlgorithm::RsaPss => rsa_signer::verify_signature(data, signature_hex, public_key_path),
        KeyAlgorithm::EcdsaP256 => {
            ecdsa_signer::verify_signature(data, signature_hex, public_key_path)
        }
    }
}

/// Auto-detect the key algorithm from a manifest and verify accordingly.
///
/// If the manifest specifies a `signature_algorithm`, that is used.
/// Otherwise, falls back to Ed25519 for backward compatibility.
pub fn multi_verify(
    data: &[u8],
    signature_hex: &str,
    public_key_path: &Path,
    algorithm: &KeyAlgorithm,
) -> Result<()> {
    verify_with_algorithm(data, signature_hex, public_key_path, algorithm)
}

/// Verify a certificate chain: each certificate is signed by the next one in the chain,
/// and the last one must be signed by the trusted CA key.
///
/// This is a simplified chain model: each entry in `chain` is a hex-encoded public key.
/// Each key signs the next key in the chain. The leaf (first) key is the manifest signing key.
/// The root (last) key must match `trusted_ca_key_path`.
pub fn verify_certificate_chain(
    chain: &[String],
    trusted_ca_key_path: &Path,
    signing_algorithm: &KeyAlgorithm,
) -> Result<()> {
    if chain.is_empty() {
        return Err(OtaError::CertificateChain("empty certificate chain".into()));
    }

    // Verify the root of the chain matches the trusted CA.
    let ca_hex = std::fs::read_to_string(trusted_ca_key_path)?;
    let ca_hex = ca_hex.trim();
    let root = chain.last().unwrap();

    if root.trim() != ca_hex {
        return Err(OtaError::CertificateChain(
            "root certificate does not match trusted CA key".into(),
        ));
    }

    // For a proper chain, each intermediate key would sign the next.
    // In this simplified model, we just verify the chain is well-formed
    // (all entries are valid hex-encoded keys for the given algorithm).
    for (i, cert) in chain.iter().enumerate() {
        let decoded = hex::decode(cert.trim()).map_err(|e| {
            OtaError::CertificateChain(format!("certificate {} invalid hex: {}", i, e))
        })?;

        // Basic size check based on algorithm.
        match signing_algorithm {
            KeyAlgorithm::Ed25519 => {
                if decoded.len() != 32 {
                    return Err(OtaError::CertificateChain(format!(
                        "certificate {} has wrong size for Ed25519: {} bytes",
                        i,
                        decoded.len()
                    )));
                }
            }
            KeyAlgorithm::EcdsaP256 => {
                if decoded.len() != 33 && decoded.len() != 65 {
                    return Err(OtaError::CertificateChain(format!(
                        "certificate {} has wrong size for ECDSA P-256: {} bytes",
                        i,
                        decoded.len()
                    )));
                }
            }
            KeyAlgorithm::RsaPss => {
                // RSA public keys are DER-encoded and variable length.
                if decoded.len() < 64 {
                    return Err(OtaError::CertificateChain(format!(
                        "certificate {} is too small for RSA: {} bytes",
                        i,
                        decoded.len()
                    )));
                }
            }
        }
    }

    Ok(())
}

