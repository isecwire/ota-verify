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

fn cmd_verify(
    manifest_path: &PathBuf,
    package_dir: &PathBuf,
    public_key: &PathBuf,
    signature: &PathBuf,
    max_age: u64,
    algorithm: Option<&AlgorithmArg>,
    policy_path: Option<&PathBuf>,
    audit_log_path: Option<&PathBuf>,
    ca_key: Option<&PathBuf>,
) -> Result<()> {
    let manifest = OtaManifest::from_file(manifest_path)?;

    let policy = match policy_path {
        Some(p) => Some(VerificationPolicy::from_file(p)?),
        None => None,
    };

    let config = VerifyConfig {
        package_dir: package_dir.clone(),
        public_key_path: public_key.clone(),
        signature_path: signature.clone(),
        max_age_hours: max_age,
        algorithm: algorithm.map(|a| a.to_key_algorithm()),
        policy,
        audit_log_path: audit_log_path.cloned(),
        manifest_path: Some(manifest_path.clone()),
        ca_key_path: ca_key.cloned(),
    };

    let verifier = OtaVerifier::new(config);
    let checks = verifier.verify(&manifest)?;

    display::print_verification_report(&checks, &manifest);

    if let Some(log_path) = audit_log_path {
        println!();
        println!("  Audit log written to: {}", log_path.display());
    }

    Ok(())
}

fn cmd_batch(
    batch_dir: &PathBuf,
    public_key: &PathBuf,
    max_age: u64,
    algorithm: Option<&AlgorithmArg>,
    policy_path: Option<&PathBuf>,
) -> Result<()> {
    let policy = match policy_path {
        Some(p) => Some(VerificationPolicy::from_file(p)?),
        None => None,
    };

    let results = verifier::batch_verify(
        batch_dir,
        public_key,
        max_age,
        algorithm.map(|a| a.to_key_algorithm()),
        policy.as_ref(),
    )?;

    display::print_batch_summary(&results);

    let failed = results.iter().filter(|(_, ok, _)| !*ok).count();
    if failed > 0 {
        return Err(errors::OtaError::BatchFailure {
            count: failed,
            total: results.len(),
        });
    }

    Ok(())
}

fn cmd_inspect(manifest_path: &PathBuf) -> Result<()> {
    let manifest = OtaManifest::from_file(manifest_path)?;
    manifest.print_summary();
    Ok(())
}

fn cmd_info(manifest_path: &PathBuf) -> Result<()> {
    let manifest = OtaManifest::from_file(manifest_path)?;
    display::print_manifest_info(&manifest);
    Ok(())
}

fn cmd_keygen(secret_path: &PathBuf, public_path: &PathBuf, algorithm: &AlgorithmArg) -> Result<()> {
    let algo = algorithm.to_key_algorithm();
    crypto::generate_keypair_for_algorithm(&algo, secret_path, public_path)?;

    use colored::Colorize;
    println!();
    println!(
        "{} {} keypair generated:",
        "\u{2713}".green().bold(),
        algo.to_string().cyan()
    );
    println!("  Secret key: {}", secret_path.display());
    println!("  Public key: {}", public_path.display());
    println!();
    println!("Keep the secret key safe. Distribute the public key to devices.");
    Ok(())
}

fn cmd_sign(
    manifest_path: &PathBuf,
    secret_key_path: &PathBuf,
    output_path: &PathBuf,
    algorithm: &AlgorithmArg,
) -> Result<()> {
    let manifest = OtaManifest::from_file(manifest_path)?;
    let canonical = manifest.to_canonical_json()?;
    let algo = algorithm.to_key_algorithm();
    let signature = crypto::sign_bytes_with_algorithm(&canonical, secret_key_path, &algo)?;

    std::fs::write(output_path, &signature)?;

    use colored::Colorize;
    println!();
    println!(
        "{} Manifest signed successfully.",
        "\u{2713}".green().bold()
    );
    println!("  Algorithm: {}", algo.to_string().cyan());
    println!("  Manifest:  {}", manifest_path.display());
    println!("  Signature: {}", output_path.display());
    println!("  Version:   {}", manifest.version);
    Ok(())
}

fn cmd_policy(action: PolicyAction) -> Result<()> {
    match action {
        PolicyAction::Validate { file } => {
            let policy = VerificationPolicy::from_file(&file)?;
            use colored::Colorize;
            println!(
                "{} Policy '{}' is valid.",
                "\u{2713}".green().bold(),
                policy.name.cyan()
            );
            Ok(())
        }
        PolicyAction::Generate { output, strict } => {
            let policy = if strict {
                VerificationPolicy::strict_example()
            } else {
                VerificationPolicy::default()
            };
            policy.save(&output)?;
            use colored::Colorize;
            println!(
                "{} Policy '{}' written to {}",
                "\u{2713}".green().bold(),
                policy.name.cyan(),
                output.display()
            );
            Ok(())
        }
        PolicyAction::Show { file } => {
            let policy = VerificationPolicy::from_file(&file)?;
            display::print_policy_info(&policy);
            Ok(())
        }
        PolicyAction::Evaluate { policy, manifest } => {
            let pol = VerificationPolicy::from_file(&policy)?;
            let man = OtaManifest::from_file(&manifest)?;
            let violations = pol.evaluate(&man);
            if violations.is_empty() {
                display::print_policy_pass(&pol.name);
            } else {
                display::print_policy_violations(&violations);
                return Err(errors::OtaError::PolicyViolation(
                    violations.join("; "),
                ));
            }
            Ok(())
        }
    }
}
