use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtaError {
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("manifest parse error: {0}")]
    ManifestParse(String),

    #[error("partition file missing: {0}")]
    PartitionFileMissing(String),

    #[error("hash mismatch for partition '{name}': expected {expected}, got {actual}")]
    HashMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    #[error("version rollback rejected: package version {package} <= rollback version {rollback}")]
    RollbackViolation { package: String, rollback: String },

    #[error("manifest expired: timestamp {timestamp} is older than {max_age_hours} hours")]
    ManifestExpired {
        timestamp: String,
        max_age_hours: u64,
    },

    #[error("key generation error: {0}")]
    KeyGeneration(String),

    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("device compatibility error: {0}")]
    DeviceIncompatible(String),

    #[error("dependency not met: {0}")]
    DependencyNotMet(String),

    #[error("size constraint violated: {0}")]
    SizeConstraint(String),

    #[error("certificate chain error: {0}")]
    CertificateChain(String),

    #[error("batch verification error: {count} of {total} packages failed")]
    BatchFailure { count: usize, total: usize },

    #[error("hook verification failed: {0}")]
    HookVerification(String),

    #[error("manifest version unsupported: {0}")]
    ManifestVersionUnsupported(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Ed25519 signature error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("ECDSA error: {0}")]
    Ecdsa(String),
}

pub type Result<T> = std::result::Result<T, OtaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_signature_invalid() {
        let e = OtaError::SignatureInvalid("bad sig".into());
        assert_eq!(format!("{e}"), "signature verification failed: bad sig");
    }

    #[test]
    fn display_manifest_parse() {
        let e = OtaError::ManifestParse("unexpected token".into());
        assert_eq!(format!("{e}"), "manifest parse error: unexpected token");
    }

    #[test]
    fn display_partition_file_missing() {
        let e = OtaError::PartitionFileMissing("rootfs".into());
        assert_eq!(format!("{e}"), "partition file missing: rootfs");
    }

    #[test]
    fn display_hash_mismatch() {
        let e = OtaError::HashMismatch {
            name: "kernel".into(),
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert_eq!(
            format!("{e}"),
            "hash mismatch for partition 'kernel': expected aaa, got bbb"
        );
    }

    #[test]
    fn display_rollback_violation() {
        let e = OtaError::RollbackViolation {
            package: "1.0.0".into(),
            rollback: "1.0.0".into(),
        };
        assert_eq!(
            format!("{e}"),
            "version rollback rejected: package version 1.0.0 <= rollback version 1.0.0"
        );
    }

    #[test]
    fn display_manifest_expired() {
        let e = OtaError::ManifestExpired {
            timestamp: "2025-01-01T00:00:00Z".into(),
            max_age_hours: 72,
        };
        assert_eq!(
            format!("{e}"),
            "manifest expired: timestamp 2025-01-01T00:00:00Z is older than 72 hours"
        );
    }

    #[test]
    fn display_key_generation() {
        let e = OtaError::KeyGeneration("rng failure".into());
        assert_eq!(format!("{e}"), "key generation error: rng failure");
    }

    #[test]
    fn display_hex_decode() {
        let inner = hex::decode("zz").unwrap_err();
        let e = OtaError::HexDecode(inner);
        let msg = format!("{e}");
        assert!(msg.contains("hex decode error"), "got: {msg}");
    }

    #[test]
    fn display_policy_violation() {
        let e = OtaError::PolicyViolation("Ed25519 required".into());
        assert_eq!(format!("{e}"), "policy violation: Ed25519 required");
    }

    #[test]
    fn display_device_incompatible() {
        let e = OtaError::DeviceIncompatible("hw_rev v2 not supported".into());
        assert_eq!(
            format!("{e}"),
            "device compatibility error: hw_rev v2 not supported"
        );
    }

    #[test]
    fn display_batch_failure() {
        let e = OtaError::BatchFailure {
            count: 3,
            total: 10,
        };
        assert_eq!(
            format!("{e}"),
            "batch verification error: 3 of 10 packages failed"
        );
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OtaError>();
    }
}
