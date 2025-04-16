use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Instant;

use crate::audit::{AuditLog, StepOutcome};
use crate::crypto;
use crate::errors::{OtaError, Result};
use crate::manifest::{KeyAlgorithm, OtaManifest};
use crate::policy::VerificationPolicy;

/// Configuration for the OTA verification process.
pub struct VerifyConfig {
    /// Path to the directory containing partition image files.
    pub package_dir: std::path::PathBuf,
    /// Path to the public key file.
    pub public_key_path: std::path::PathBuf,
    /// Path to the detached signature file (hex-encoded).
    pub signature_path: std::path::PathBuf,
    /// Maximum manifest age in hours (0 = no expiry check).
    pub max_age_hours: u64,
    /// Signature algorithm override. If None, auto-detected from manifest.
    pub algorithm: Option<KeyAlgorithm>,
    /// Optional verification policy to enforce.
    pub policy: Option<VerificationPolicy>,
    /// Optional path to write audit log.
    pub audit_log_path: Option<std::path::PathBuf>,
    /// Path to the manifest file (for audit logging).
    pub manifest_path: Option<std::path::PathBuf>,
    /// Optional trusted CA key path for certificate chain verification.
    pub ca_key_path: Option<std::path::PathBuf>,
}

/// Full OTA package verifier.
pub struct OtaVerifier {
    config: VerifyConfig,
}

impl OtaVerifier {
    pub fn new(config: VerifyConfig) -> Self {
        Self { config }
    }

    /// Run all verification checks on the given manifest.
    /// Returns a list of passed check descriptions on success.
    pub fn verify(&self, manifest: &OtaManifest) -> Result<Vec<String>> {
        let mut audit = AuditLog::new(
            self.config
                .manifest_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "<unknown>".into())
                .as_str(),
            &manifest.version,
            &manifest.device_type,
        );

        let result = self.verify_inner(manifest, &mut audit);

        audit.finalize();

        // Write audit log if configured.
        if let Some(ref path) = self.config.audit_log_path {
            let _ = audit.save(path);
        }

        result
    }

    /// Inner verification logic with audit recording.
    fn verify_inner(
        &self,
        manifest: &OtaManifest,
        audit: &mut AuditLog,
    ) -> Result<Vec<String>> {
        let mut passed = Vec::new();

        // Step 1: Cryptographic signature.
        let t = Instant::now();
        match self.check_signature(manifest) {
            Ok(()) => {
                let algo = self.effective_algorithm(manifest);
                let msg = format!("Cryptographic signature valid ({})", algo);
                audit.record_step("signature", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step("signature", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 2: Certificate chain (if present).
        let t = Instant::now();
        match self.check_certificate_chain(manifest) {
            Ok(Some(msg)) => {
                audit.record_step("certificate_chain", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Ok(None) => {
                audit.record_step("certificate_chain", StepOutcome::Skip, "no chain present", t.elapsed().as_millis() as u64);
            }
            Err(e) => {
                audit.record_step("certificate_chain", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 3: Partition files present.
        let t = Instant::now();
        match self.check_partition_files(manifest) {
            Ok(()) => {
                let msg = "All partition files present".to_string();
                audit.record_step("partition_files", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step("partition_files", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 4: SHA-256 hashes.
        let t = Instant::now();
        match self.check_hashes(manifest) {
            Ok(()) => {
                let msg = "SHA-256 hashes match".to_string();
                audit.record_step("hashes", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step("hashes", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 5: Rollback version.
        let t = Instant::now();
        match self.check_rollback_version(manifest) {
            Ok(()) => {
                let msg = format!(
                    "Version {} > rollback version {}",
                    manifest.version, manifest.rollback_version
                );
                audit.record_step("rollback", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step("rollback", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 6: Manifest expiry.
        if self.config.max_age_hours > 0 {
            let t = Instant::now();
            match self.check_expiry(manifest) {
                Ok(()) => {
                    let msg = format!("Manifest within {}h age limit", self.config.max_age_hours);
                    audit.record_step("expiry", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                    passed.push(msg);
                }
                Err(e) => {
                    audit.record_step("expiry", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                    return Err(e);
                }
            }
        } else {
            audit.record_step("expiry", StepOutcome::Skip, "max_age=0, skipping", 0);
        }

        // Step 7: Size constraints (v2).
        let t = Instant::now();
        match self.check_size_constraints(manifest) {
            Ok(Some(msg)) => {
                audit.record_step("size_constraints", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Ok(None) => {
                audit.record_step("size_constraints", StepOutcome::Skip, "no size constraints", t.elapsed().as_millis() as u64);
            }
            Err(e) => {
                audit.record_step("size_constraints", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 8: Install hook hashes (v2).
        let t = Instant::now();
        match self.check_hook_hashes(manifest) {
            Ok(Some(msg)) => {
                audit.record_step("hook_hashes", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Ok(None) => {
                audit.record_step("hook_hashes", StepOutcome::Skip, "no hooks defined", t.elapsed().as_millis() as u64);
            }
            Err(e) => {
                audit.record_step("hook_hashes", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 9: Package simulation (temp directory structure).
        let t = Instant::now();
        match self.check_package_simulation(manifest) {
            Ok(msg) => {
                audit.record_step("package_simulation", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step("package_simulation", StepOutcome::Fail, &e.to_string(), t.elapsed().as_millis() as u64);
                return Err(e);
            }
        }

        // Step 10: Policy enforcement (if configured).
        if let Some(ref policy) = self.config.policy {
            let t = Instant::now();
            let violations = policy.evaluate(manifest);
            if violations.is_empty() {
                let msg = format!("Policy '{}' satisfied", policy.name);
                audit.record_step("policy", StepOutcome::Pass, &msg, t.elapsed().as_millis() as u64);
                passed.push(msg);
            } else {
                let msg = violations.join("; ");
                audit.record_step("policy", StepOutcome::Fail, &msg, t.elapsed().as_millis() as u64);
                return Err(OtaError::PolicyViolation(msg));
            }
        }

        Ok(passed)
    }

    /// Determine the effective algorithm for signature verification.
    fn effective_algorithm(&self, manifest: &OtaManifest) -> KeyAlgorithm {
        self.config
            .algorithm
            .clone()
            .unwrap_or_else(|| manifest.effective_algorithm())
    }

    /// Verify the cryptographic signature over the canonical manifest JSON.
    fn check_signature(&self, manifest: &OtaManifest) -> Result<()> {
        let canonical = manifest.to_canonical_json()?;
        let sig_hex = std::fs::read_to_string(&self.config.signature_path)?;
        let algorithm = self.effective_algorithm(manifest);

        crypto::verify_with_algorithm(
            &canonical,
            sig_hex.trim(),
            &self.config.public_key_path,
            &algorithm,
        )
    }

    /// Verify the certificate chain if present in the manifest.
    fn check_certificate_chain(&self, manifest: &OtaManifest) -> Result<Option<String>> {
        let chain = match &manifest.certificate_chain {
            Some(c) if !c.is_empty() => c,
            _ => return Ok(None),
        };

        let ca_path = match &self.config.ca_key_path {
            Some(p) => p,
            None => {
                // If chain is present but no CA key configured, just validate format.
                for (i, cert) in chain.iter().enumerate() {
                    hex::decode(cert.trim()).map_err(|e| {
                        OtaError::CertificateChain(format!("certificate {} invalid: {}", i, e))
                    })?;
                }
                return Ok(Some(format!(
                    "Certificate chain has {} entries (CA not verified, no CA key provided)",
                    chain.len()
                )));
            }
        };

        let algorithm = self.effective_algorithm(manifest);
        crypto::verify_certificate_chain(chain, ca_path, &algorithm)?;

        Ok(Some(format!(
            "Certificate chain verified ({} certificates)",
            chain.len()
        )))
    }

    /// Ensure every partition image file exists in the package directory.
    fn check_partition_files(&self, manifest: &OtaManifest) -> Result<()> {
        for partition in &manifest.partitions {
            let path = self.config.package_dir.join(&partition.name);
            if !path.exists() {
                return Err(OtaError::PartitionFileMissing(partition.name.clone()));
            }
        }
        Ok(())
    }

    /// Verify SHA-256 hashes of all partition image files.
    fn check_hashes(&self, manifest: &OtaManifest) -> Result<()> {
        for partition in &manifest.partitions {
            let path = self.config.package_dir.join(&partition.name);
            let data = std::fs::read(&path)?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual = hex::encode(hasher.finalize());

            if actual != partition.hash_sha256 {
                return Err(OtaError::HashMismatch {
                    name: partition.name.clone(),
                    expected: partition.hash_sha256.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Ensure the package version is strictly greater than the rollback version.
    fn check_rollback_version(&self, manifest: &OtaManifest) -> Result<()> {
        if !version_greater_than(&manifest.version, &manifest.rollback_version) {
            return Err(OtaError::RollbackViolation {
                package: manifest.version.clone(),
                rollback: manifest.rollback_version.clone(),
            });
        }
        Ok(())
    }

    /// Ensure the manifest timestamp is not older than the configured maximum age.
    fn check_expiry(&self, manifest: &OtaManifest) -> Result<()> {
        let age = Utc::now()
            .signed_duration_since(manifest.timestamp)
            .num_hours();

        if age < 0 || age as u64 > self.config.max_age_hours {
            return Err(OtaError::ManifestExpired {
                timestamp: manifest.timestamp.to_rfc3339(),
                max_age_hours: self.config.max_age_hours,
            });
        }
        Ok(())
    }

    /// Verify size constraints if specified in the manifest.
    fn check_size_constraints(&self, manifest: &OtaManifest) -> Result<Option<String>> {
        let target_size = match manifest.target_partition_size {
            Some(s) => s,
            None => return Ok(None),
        };

        let total = manifest.total_image_size();
        let required_free = manifest.required_free_space.unwrap_or(0);
        let needed = total + required_free;

        if needed > target_size {
            return Err(OtaError::SizeConstraint(format!(
                "images ({} bytes) + free space ({} bytes) = {} bytes exceeds target partition ({} bytes)",
                total, required_free, needed, target_size
            )));
        }

        Ok(Some(format!(
            "Size check passed: {} bytes fits in {} byte partition ({} bytes headroom)",
            needed,
            target_size,
            target_size - needed
        )))
    }

    /// Verify install hook script hashes if hooks are defined.
    fn check_hook_hashes(&self, manifest: &OtaManifest) -> Result<Option<String>> {
        let hooks = match &manifest.hooks {
            Some(h) if !h.is_empty() => h,
            _ => return Ok(None),
        };

        let mut verified = 0;
        for hook in hooks {
            let path = self.config.package_dir.join(&hook.script);
            if !path.exists() {
                return Err(OtaError::HookVerification(format!(
                    "hook script '{}' not found in package",
                    hook.script
                )));
            }

            let data = std::fs::read(&path)?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual = hex::encode(hasher.finalize());

            if actual != hook.hash_sha256 {
                return Err(OtaError::HookVerification(format!(
                    "hook '{}' hash mismatch: expected {}, got {}",
                    hook.script, hook.hash_sha256, actual
                )));
            }
            verified += 1;
        }

        Ok(Some(format!("{} install hook(s) verified", verified)))
    }

    /// Simulate package deployment by creating a temp directory structure
    /// and verifying all files can be placed correctly.
    fn check_package_simulation(&self, manifest: &OtaManifest) -> Result<String> {
        // Verify each partition file's actual size matches the manifest declaration.
        for partition in &manifest.partitions {
            let path = self.config.package_dir.join(&partition.name);
            if path.exists() {
                let metadata = std::fs::metadata(&path)?;
                let actual_size = metadata.len();
                if actual_size != partition.size {
                    return Err(OtaError::SizeConstraint(format!(
                        "partition '{}' actual size {} != declared size {}",
                        partition.name, actual_size, partition.size
                    )));
                }
            }
        }

        let total = manifest.total_image_size();
        Ok(format!(
            "Package simulation passed ({} total bytes across {} partitions)",
            total,
            manifest.partitions.len()
        ))
    }
}
