mod audit;
mod crypto;
mod display;
mod ecdsa_signer;
mod errors;
mod manifest;
mod policy;
mod rsa_signer;
mod verifier;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::errors::Result;
use crate::manifest::{KeyAlgorithm, OtaManifest};
use crate::policy::VerificationPolicy;
use crate::verifier::{OtaVerifier, VerifyConfig};

/// CLI-level algorithm selector that maps to manifest::KeyAlgorithm.
#[derive(Debug, Clone, ValueEnum)]
enum AlgorithmArg {
    Ed25519,
    Rsa,
    EcdsaP256,
}

impl AlgorithmArg {
    fn to_key_algorithm(&self) -> KeyAlgorithm {
        match self {
            AlgorithmArg::Ed25519 => KeyAlgorithm::Ed25519,
            AlgorithmArg::Rsa => KeyAlgorithm::RsaPss,
            AlgorithmArg::EcdsaP256 => KeyAlgorithm::EcdsaP256,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "ota-verify",
    version,
    about = "OTA update package verifier for embedded device firmware",
    long_about = "Validates cryptographic signatures, manifest integrity, and simulates \
                  A/B partition rollback for embedded device firmware updates.\n\n\
                  Supports Ed25519, RSA (PKCS#1 v1.5 + SHA-256), and ECDSA P-256 signatures.\n\
                  Includes policy engine, audit logging, batch verification, and certificate chain support."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify an OTA update package
    Verify {
        /// Path to the manifest JSON file
        #[arg(short, long)]
        manifest: PathBuf,

        /// Path to the package directory containing partition images
        #[arg(short, long)]
        package_dir: PathBuf,

        /// Path to the public key file
        #[arg(short = 'k', long)]
        public_key: PathBuf,

        /// Path to the detached signature file
        #[arg(short, long)]
        signature: PathBuf,

        /// Maximum manifest age in hours (0 = no expiry check)
        #[arg(long, default_value = "72")]
        max_age: u64,

        /// Signature algorithm (auto-detected from manifest if not specified)
        #[arg(long, value_enum)]
        algorithm: Option<AlgorithmArg>,

        /// Path to a verification policy JSON file
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Path to write a JSON audit log
        #[arg(long)]
        audit_log: Option<PathBuf>,

        /// Path to trusted CA public key for certificate chain verification
        #[arg(long)]
        ca_key: Option<PathBuf>,
    },

    /// Verify multiple OTA packages from a directory (batch mode)
    Batch {
        /// Path to directory containing package subdirectories
        #[arg(short, long)]
        dir: PathBuf,

        /// Path to the public key file
        #[arg(short = 'k', long)]
        public_key: PathBuf,

        /// Maximum manifest age in hours (0 = no expiry check)
        #[arg(long, default_value = "72")]
        max_age: u64,

        /// Signature algorithm override
        #[arg(long, value_enum)]
        algorithm: Option<AlgorithmArg>,

        /// Path to a verification policy JSON file
        #[arg(long)]
        policy: Option<PathBuf>,
    },

    /// Inspect an OTA manifest file (basic summary)
    Inspect {
        /// Path to the manifest JSON file
        #[arg(short, long)]
        manifest: PathBuf,
    },

    /// Detailed manifest analysis with formatted output
    Info {
        /// Path to the manifest JSON file
        #[arg(short, long)]
        manifest: PathBuf,
    },

    /// Generate a new signing keypair
    Keygen {
        /// Output path for the secret key
        #[arg(short, long, default_value = "ota-secret.key")]
        secret: PathBuf,

        /// Output path for the public key
        #[arg(short, long, default_value = "ota-public.key")]
        public: PathBuf,

        /// Key algorithm to generate
        #[arg(long, value_enum, default_value = "ed25519")]
        algorithm: AlgorithmArg,
    },

    /// Sign an OTA manifest file
    Sign {
        /// Path to the manifest JSON file
        #[arg(short, long)]
        manifest: PathBuf,

        /// Path to the secret key file
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// Output path for the detached signature
        #[arg(short, long, default_value = "manifest.sig")]
        output: PathBuf,

        /// Signature algorithm
        #[arg(long, value_enum, default_value = "ed25519")]
        algorithm: AlgorithmArg,
    },

    /// Validate or generate verification policy files
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate a policy JSON file
    Validate {
        /// Path to the policy file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Generate an example policy file
    Generate {
        /// Output path
        #[arg(short, long, default_value = "policy.json")]
        output: PathBuf,

        /// Generate a strict production policy instead of default
        #[arg(long)]
        strict: bool,
    },

    /// Show a formatted summary of a policy
    Show {
        /// Path to the policy file
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Evaluate a policy against a manifest (dry-run, no signature check)
    Evaluate {
        /// Path to the policy file
        #[arg(short, long)]
        policy: PathBuf,

        /// Path to the manifest JSON file
        #[arg(short, long)]
        manifest: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        display::print_verification_failure(&e.to_string());
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Verify {
            manifest,
            package_dir,
            public_key,
            signature,
            max_age,
            algorithm,
            policy,
            audit_log,
            ca_key,
        } => cmd_verify(
            &manifest,
            &package_dir,
            &public_key,
            &signature,
            max_age,
            algorithm.as_ref(),
            policy.as_ref(),
            audit_log.as_ref(),
            ca_key.as_ref(),
        ),
        Commands::Batch {
            dir,
            public_key,
            max_age,
            algorithm,
            policy,
        } => cmd_batch(&dir, &public_key, max_age, algorithm.as_ref(), policy.as_ref()),
        Commands::Inspect { manifest } => cmd_inspect(&manifest),
        Commands::Info { manifest } => cmd_info(&manifest),
        Commands::Keygen {
            secret,
            public,
            algorithm,
        } => cmd_keygen(&secret, &public, &algorithm),
        Commands::Sign {
            manifest,
            secret_key,
            output,
            algorithm,
        } => cmd_sign(&manifest, &secret_key, &output, &algorithm),
        Commands::Policy { action } => cmd_policy(action),
    }
}
