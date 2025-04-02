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

