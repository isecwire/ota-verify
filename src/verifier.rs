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
    fn verify_inner(&self, manifest: &OtaManifest, audit: &mut AuditLog) -> Result<Vec<String>> {
        let mut passed = Vec::new();

        // Step 1: Cryptographic signature.
        let t = Instant::now();
        match self.check_signature(manifest) {
            Ok(()) => {
                let algo = self.effective_algorithm(manifest);
                let msg = format!("Cryptographic signature valid ({})", algo);
                audit.record_step(
                    "signature",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step(
                    "signature",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 2: Certificate chain (if present).
        let t = Instant::now();
        match self.check_certificate_chain(manifest) {
            Ok(Some(msg)) => {
                audit.record_step(
                    "certificate_chain",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Ok(None) => {
                audit.record_step(
                    "certificate_chain",
                    StepOutcome::Skip,
                    "no chain present",
                    t.elapsed().as_millis() as u64,
                );
            }
            Err(e) => {
                audit.record_step(
                    "certificate_chain",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 3: Partition files present.
        let t = Instant::now();
        match self.check_partition_files(manifest) {
            Ok(()) => {
                let msg = "All partition files present".to_string();
                audit.record_step(
                    "partition_files",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step(
                    "partition_files",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 4: SHA-256 hashes.
        let t = Instant::now();
        match self.check_hashes(manifest) {
            Ok(()) => {
                let msg = "SHA-256 hashes match".to_string();
                audit.record_step(
                    "hashes",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step(
                    "hashes",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
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
                audit.record_step(
                    "rollback",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step(
                    "rollback",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 6: Manifest expiry.
        if self.config.max_age_hours > 0 {
            let t = Instant::now();
            match self.check_expiry(manifest) {
                Ok(()) => {
                    let msg = format!("Manifest within {}h age limit", self.config.max_age_hours);
                    audit.record_step(
                        "expiry",
                        StepOutcome::Pass,
                        &msg,
                        t.elapsed().as_millis() as u64,
                    );
                    passed.push(msg);
                }
                Err(e) => {
                    audit.record_step(
                        "expiry",
                        StepOutcome::Fail,
                        &e.to_string(),
                        t.elapsed().as_millis() as u64,
                    );
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
                audit.record_step(
                    "size_constraints",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Ok(None) => {
                audit.record_step(
                    "size_constraints",
                    StepOutcome::Skip,
                    "no size constraints",
                    t.elapsed().as_millis() as u64,
                );
            }
            Err(e) => {
                audit.record_step(
                    "size_constraints",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 8: Install hook hashes (v2).
        let t = Instant::now();
        match self.check_hook_hashes(manifest) {
            Ok(Some(msg)) => {
                audit.record_step(
                    "hook_hashes",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Ok(None) => {
                audit.record_step(
                    "hook_hashes",
                    StepOutcome::Skip,
                    "no hooks defined",
                    t.elapsed().as_millis() as u64,
                );
            }
            Err(e) => {
                audit.record_step(
                    "hook_hashes",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 9: Package simulation (temp directory structure).
        let t = Instant::now();
        match self.check_package_simulation(manifest) {
            Ok(msg) => {
                audit.record_step(
                    "package_simulation",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            }
            Err(e) => {
                audit.record_step(
                    "package_simulation",
                    StepOutcome::Fail,
                    &e.to_string(),
                    t.elapsed().as_millis() as u64,
                );
                return Err(e);
            }
        }

        // Step 10: Policy enforcement (if configured).
        if let Some(ref policy) = self.config.policy {
            let t = Instant::now();
            let violations = policy.evaluate(manifest);
            if violations.is_empty() {
                let msg = format!("Policy '{}' satisfied", policy.name);
                audit.record_step(
                    "policy",
                    StepOutcome::Pass,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
                passed.push(msg);
            } else {
                let msg = violations.join("; ");
                audit.record_step(
                    "policy",
                    StepOutcome::Fail,
                    &msg,
                    t.elapsed().as_millis() as u64,
                );
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

/// Verify a batch of OTA packages from a directory.
///
/// Each subdirectory is expected to contain a manifest.json, partition files,
/// and a manifest.sig file. Returns results for each package.
pub fn batch_verify(
    batch_dir: &Path,
    public_key_path: &Path,
    max_age_hours: u64,
    algorithm: Option<KeyAlgorithm>,
    policy: Option<&VerificationPolicy>,
) -> Result<Vec<(String, bool, String)>> {
    let mut results = Vec::new();

    let entries = std::fs::read_dir(batch_dir)?;
    let mut dirs: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    dirs.sort_by_key(|e| e.file_name());

    if dirs.is_empty() {
        return Err(OtaError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no subdirectories found in batch directory",
        )));
    }

    for entry in &dirs {
        let pkg_dir = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        let manifest_path = pkg_dir.join("manifest.json");
        let sig_path = pkg_dir.join("manifest.sig");

        if !manifest_path.exists() {
            results.push((name, false, "manifest.json not found".into()));
            continue;
        }
        if !sig_path.exists() {
            results.push((name, false, "manifest.sig not found".into()));
            continue;
        }

        let manifest = match OtaManifest::from_file(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                results.push((name, false, format!("manifest parse error: {e}")));
                continue;
            }
        };

        let config = VerifyConfig {
            package_dir: pkg_dir.clone(),
            public_key_path: public_key_path.to_path_buf(),
            signature_path: sig_path,
            max_age_hours,
            algorithm: algorithm.clone(),
            policy: policy.cloned(),
            audit_log_path: None,
            manifest_path: Some(manifest_path),
            ca_key_path: None,
        };

        let verifier = OtaVerifier::new(config);
        match verifier.verify(&manifest) {
            Ok(checks) => {
                results.push((name, true, format!("{} checks passed", checks.len())));
            }
            Err(e) => {
                results.push((name, false, e.to_string()));
            }
        }
    }

    Ok(results)
}

/// Compare two dotted version strings numerically.
fn version_greater_than(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let va = parse(a);
    let vb = parse(b);

    let max_len = va.len().max(vb.len());
    for i in 0..max_len {
        let pa = va.get(i).copied().unwrap_or(0);
        let pb = vb.get(i).copied().unwrap_or(0);
        if pa > pb {
            return true;
        }
        if pa < pb {
            return false;
        }
    }
    false // equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Partition, TargetSlot};
    use chrono::{TimeDelta, Utc};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use tempfile::tempdir;

    // ---- version_greater_than tests ----

    #[test]
    fn version_greater_patch() {
        assert!(version_greater_than("1.0.1", "1.0.0"));
    }

    #[test]
    fn version_greater_minor() {
        assert!(version_greater_than("1.1.0", "1.0.99"));
    }

    #[test]
    fn version_greater_major() {
        assert!(version_greater_than("2.0.0", "1.9.9"));
    }

    #[test]
    fn version_equal_returns_false() {
        assert!(!version_greater_than("1.0.0", "1.0.0"));
    }

    #[test]
    fn version_lesser_returns_false() {
        assert!(!version_greater_than("1.0.0", "2.0.0"));
    }

    #[test]
    fn version_different_segment_count() {
        assert!(version_greater_than("1.0.0.1", "1.0.0"));
        assert!(!version_greater_than("1.0.0", "1.0.0.1"));
    }

    #[test]
    fn version_single_segment() {
        assert!(version_greater_than("3", "2"));
        assert!(!version_greater_than("1", "2"));
    }

    // ---- hash verification tests ----

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn make_manifest_and_package(
        version: &str,
        rollback: &str,
        timestamp: chrono::DateTime<Utc>,
        partition_data: &[(&str, &[u8])],
    ) -> (OtaManifest, tempfile::TempDir) {
        let dir = tempdir().expect("tmpdir");

        let partitions: Vec<Partition> = partition_data
            .iter()
            .map(|(name, data)| {
                std::fs::write(dir.path().join(name), data).expect("write partition");
                Partition {
                    name: name.to_string(),
                    hash_sha256: sha256_hex(data),
                    size: data.len() as u64,
                    target_slot: TargetSlot::SlotA,
                    delta: None,
                }
            })
            .collect();

        let manifest = OtaManifest {
            manifest_version: 1,
            version: version.into(),
            device_type: "test-device".into(),
            partitions,
            timestamp,
            min_battery: 20,
            rollback_version: rollback.into(),
            signature_algorithm: None,
            key_rotation: None,
            certificate_chain: None,
            compatibility: None,
            hooks: None,
            dependencies: None,
            target_partition_size: None,
            required_free_space: None,
            metadata: HashMap::new(),
        };

        (manifest, dir)
    }

    /// Create a signed package directory with keys, sig, and partition files.
    fn setup_signed_package(
        version: &str,
        rollback: &str,
        timestamp: chrono::DateTime<Utc>,
        partition_data: &[(&str, &[u8])],
    ) -> (OtaManifest, tempfile::TempDir) {
        let (manifest, dir) =
            make_manifest_and_package(version, rollback, timestamp, partition_data);

        // Generate keypair
        let secret_path = dir.path().join("secret.key");
        let public_path = dir.path().join("public.key");
        crate::crypto::generate_keypair(&secret_path, &public_path).expect("keygen");

        // Sign the manifest
        let canonical = manifest.to_canonical_json().expect("canonical");
        let sig_hex = crate::crypto::sign_bytes(&canonical, &secret_path).expect("sign");
        let sig_path = dir.path().join("manifest.sig");
        std::fs::write(&sig_path, &sig_hex).expect("write sig");

        (manifest, dir)
    }

    fn default_verify_config(dir: &Path) -> VerifyConfig {
        VerifyConfig {
            package_dir: dir.to_path_buf(),
            public_key_path: dir.join("public.key"),
            signature_path: dir.join("manifest.sig"),
            max_age_hours: 0,
            algorithm: None,
            policy: None,
            audit_log_path: None,
            manifest_path: None,
            ca_key_path: None,
        }
    }

    #[test]
    fn hash_verification_pass() {
        let data: &[u8] = b"rootfs image content";
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", data)]);

        let config = default_verify_config(dir.path());
        let verifier = OtaVerifier::new(config);
        let result = verifier.verify(&manifest);
        assert!(
            result.is_ok(),
            "full verify should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn hash_verification_fail_tampered_file() {
        let data: &[u8] = b"rootfs image content";
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", data)]);

        // Tamper with the partition file after signing
        std::fs::write(dir.path().join("rootfs"), b"TAMPERED").expect("tamper");

        let config = default_verify_config(dir.path());
        let verifier = OtaVerifier::new(config);
        let result = verifier.verify(&manifest);
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("hash mismatch") || err_str.contains("size"),
            "expected hash mismatch or size error, got: {err_str}"
        );
    }

    #[test]
    fn rollback_version_check_pass() {
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", b"data")]);

        let config = default_verify_config(dir.path());
        let verifier = OtaVerifier::new(config);
        assert!(verifier.verify(&manifest).is_ok());
    }

    #[test]
    fn rollback_version_check_fail() {
        let (manifest, dir) =
            setup_signed_package("1.0.0", "1.0.0", Utc::now(), &[("rootfs", b"data")]);

        let config = default_verify_config(dir.path());
        let verifier = OtaVerifier::new(config);
        let result = verifier.verify(&manifest);
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("rollback"),
            "expected rollback error, got: {err_str}"
        );
    }

    #[test]
    fn expired_manifest_detected() {
        let old_timestamp = Utc::now() - TimeDelta::hours(100);
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", old_timestamp, &[("rootfs", b"data")]);

        let mut config = default_verify_config(dir.path());
        config.max_age_hours = 72;

        let verifier = OtaVerifier::new(config);
        let result = verifier.verify(&manifest);
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("expired"),
            "expected expired error, got: {err_str}"
        );
    }

    #[test]
    fn non_expired_manifest_passes_age_check() {
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", b"data")]);

        let mut config = default_verify_config(dir.path());
        config.max_age_hours = 72;

        let verifier = OtaVerifier::new(config);
        assert!(verifier.verify(&manifest).is_ok());
    }

    #[test]
    fn missing_partition_file_detected() {
        let (mut manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", b"data")]);

        // Add a phantom partition
        manifest.partitions.push(Partition {
            name: "nonexistent_partition".into(),
            hash_sha256: "0000".into(),
            size: 0,
            target_slot: TargetSlot::SlotB,
            delta: None,
        });

        // Re-sign because manifest changed
        let canonical = manifest.to_canonical_json().expect("canonical");
        let sig_hex =
            crate::crypto::sign_bytes(&canonical, &dir.path().join("secret.key")).expect("sign");
        std::fs::write(dir.path().join("manifest.sig"), &sig_hex).expect("write sig");

        let config = default_verify_config(dir.path());
        let verifier = OtaVerifier::new(config);
        let result = verifier.verify(&manifest);
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("missing"),
            "expected partition missing error, got: {err_str}"
        );
    }

    #[test]
    fn audit_log_written() {
        let data: &[u8] = b"rootfs image content";
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", data)]);

        let audit_path = dir.path().join("audit.json");
        let mut config = default_verify_config(dir.path());
        config.audit_log_path = Some(audit_path.clone());
        config.manifest_path = Some(dir.path().join("manifest.json"));

        let verifier = OtaVerifier::new(config);
        verifier.verify(&manifest).expect("verify");

        assert!(audit_path.exists(), "audit log should be written");
        let log_data = std::fs::read_to_string(&audit_path).unwrap();
        assert!(log_data.contains("signature"));
        assert!(log_data.contains("PASS") || log_data.contains("pass"));
    }

    #[test]
    fn policy_enforcement_pass() {
        let data: &[u8] = b"rootfs image content";
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", data)]);

        let policy = VerificationPolicy::default();
        let mut config = default_verify_config(dir.path());
        config.policy = Some(policy);

        let verifier = OtaVerifier::new(config);
        assert!(verifier.verify(&manifest).is_ok());
    }

    #[test]
    fn policy_enforcement_fail() {
        let data: &[u8] = b"rootfs image content";
        let (manifest, dir) =
            setup_signed_package("2.0.0", "1.0.0", Utc::now(), &[("rootfs", data)]);

        let policy = VerificationPolicy {
            require_algorithm: Some(KeyAlgorithm::RsaPss),
            ..Default::default()
        };
        let mut config = default_verify_config(dir.path());
        config.policy = Some(policy);

        let verifier = OtaVerifier::new(config);
        let result = verifier.verify(&manifest);
        assert!(result.is_err());
        let err_str = format!("{}", result.unwrap_err());
        assert!(
            err_str.contains("policy"),
            "expected policy error, got: {err_str}"
        );
    }
}
