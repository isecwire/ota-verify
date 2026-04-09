//! Verification policy engine for OTA packages.
//!
//! Policies are loaded from JSON files and define constraints that an OTA
//! manifest must satisfy beyond the basic cryptographic checks. This allows
//! fleet operators to enforce organizational security requirements.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::errors::{OtaError, Result};
use crate::manifest::{KeyAlgorithm, OtaManifest};

/// A verification policy with configurable rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    /// Human-readable policy name.
    #[serde(default = "default_policy_name")]
    pub name: String,

    /// If set, only this signature algorithm is accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_algorithm: Option<KeyAlgorithm>,

    /// Maximum manifest age in hours. 0 = no limit.
    #[serde(default)]
    pub max_age_hours: u64,

    /// Require rollback protection (version > rollback_version).
    #[serde(default = "default_true")]
    pub require_rollback_protection: bool,

    /// Minimum manifest schema version required.
    #[serde(default)]
    pub min_manifest_version: u32,

    /// If true, device compatibility matrix must be present and non-empty.
    #[serde(default)]
    pub require_compatibility_matrix: bool,

    /// If true, at least one install hook must be present.
    #[serde(default)]
    pub require_hooks: bool,

    /// If true, key rotation metadata must be present.
    #[serde(default)]
    pub require_key_rotation: bool,

    /// If true, certificate chain must be present and non-empty.
    #[serde(default)]
    pub require_certificate_chain: bool,

    /// Minimum battery level required by policy (overrides manifest if higher).
    #[serde(default)]
    pub min_battery_override: u8,

    /// Allowed device types. Empty = all allowed.
    #[serde(default)]
    pub allowed_device_types: Vec<String>,

    /// Maximum total image size in bytes. 0 = no limit.
    #[serde(default)]
    pub max_total_image_size: u64,
}

fn default_policy_name() -> String {
    "default".into()
}

fn default_true() -> bool {
    true
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            name: "default".into(),
            require_algorithm: None,
            max_age_hours: 72,
            require_rollback_protection: true,
            min_manifest_version: 0,
            require_compatibility_matrix: false,
            require_hooks: false,
            require_key_rotation: false,
            require_certificate_chain: false,
            min_battery_override: 0,
            allowed_device_types: Vec::new(),
            max_total_image_size: 0,
        }
    }
}

impl VerificationPolicy {
    /// Load a policy from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Self::from_json(&data)
    }

    /// Parse a policy from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| OtaError::PolicyViolation(format!("invalid policy: {e}")))
    }

    /// Serialize the policy to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| OtaError::PolicyViolation(e.to_string()))
    }

    /// Save the policy to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Generate a strict example policy suitable for production use.
    pub fn strict_example() -> Self {
        Self {
            name: "strict-production".into(),
            require_algorithm: Some(KeyAlgorithm::Ed25519),
            max_age_hours: 48,
            require_rollback_protection: true,
            min_manifest_version: 2,
            require_compatibility_matrix: true,
            require_hooks: false,
            require_key_rotation: false,
            require_certificate_chain: false,
            min_battery_override: 25,
            allowed_device_types: Vec::new(),
            max_total_image_size: 512 * 1024 * 1024, // 512 MiB
        }
    }

    /// Evaluate the policy against a manifest. Returns a list of violations.
    /// An empty list means the manifest passes the policy.
    pub fn evaluate(&self, manifest: &OtaManifest) -> Vec<String> {
        let mut violations = Vec::new();

        // Check signature algorithm requirement.
        if let Some(ref required) = self.require_algorithm {
            let effective = manifest.effective_algorithm();
            if &effective != required {
                violations.push(format!(
                    "policy requires algorithm {}, manifest uses {}",
                    required, effective
                ));
            }
        }

        // Check manifest version requirement.
        if self.min_manifest_version > 0 && manifest.manifest_version < self.min_manifest_version {
            violations.push(format!(
                "policy requires manifest_version >= {}, got {}",
                self.min_manifest_version, manifest.manifest_version
            ));
        }

        // Check compatibility matrix.
        if self.require_compatibility_matrix {
            match &manifest.compatibility {
                None => violations.push("policy requires device compatibility matrix".into()),
                Some(c) if c.hardware_revisions.is_empty() && c.boot_rom_versions.is_empty() => {
                    violations.push("policy requires non-empty compatibility matrix".into());
                }
                _ => {}
            }
        }

        // Check hooks requirement.
        if self.require_hooks {
            match &manifest.hooks {
                None => violations.push("policy requires install hooks".into()),
                Some(h) if h.is_empty() => {
                    violations.push("policy requires at least one install hook".into());
                }
                _ => {}
            }
        }

        // Check key rotation requirement.
        if self.require_key_rotation && manifest.key_rotation.is_none() {
            violations.push("policy requires key rotation metadata".into());
        }

        // Check certificate chain requirement.
        if self.require_certificate_chain {
            match &manifest.certificate_chain {
                None => violations.push("policy requires certificate chain".into()),
                Some(c) if c.is_empty() => {
                    violations.push("policy requires non-empty certificate chain".into());
                }
                _ => {}
            }
        }

        // Check battery level.
        if self.min_battery_override > 0 && manifest.min_battery < self.min_battery_override {
            violations.push(format!(
                "policy requires min_battery >= {}%, manifest specifies {}%",
                self.min_battery_override, manifest.min_battery
            ));
        }

        // Check allowed device types.
        if !self.allowed_device_types.is_empty()
            && !self.allowed_device_types.contains(&manifest.device_type)
        {
            violations.push(format!(
                "device type '{}' not in allowed list: {:?}",
                manifest.device_type, self.allowed_device_types
            ));
        }

        // Check total image size.
        if self.max_total_image_size > 0 {
            let total = manifest.total_image_size();
            if total > self.max_total_image_size {
                violations.push(format!(
                    "total image size {} exceeds policy limit {}",
                    total, self.max_total_image_size
                ));
            }
        }

        violations
    }

    /// Print a formatted summary of the policy.
    pub fn print_summary(&self) {
        println!("Verification Policy: {}", self.name);
        println!("{}", "=".repeat(40 + self.name.len()));

        if let Some(ref algo) = self.require_algorithm {
            println!("  Required algorithm:       {}", algo);
        } else {
            println!("  Required algorithm:       any");
        }
        println!(
            "  Max age (hours):          {}",
            if self.max_age_hours == 0 {
                "unlimited".to_string()
            } else {
                self.max_age_hours.to_string()
            }
        );
        println!(
            "  Rollback protection:      {}",
            self.require_rollback_protection
        );
        println!(
            "  Min manifest version:     {}",
            if self.min_manifest_version == 0 {
                "any".to_string()
            } else {
                format!("v{}", self.min_manifest_version)
            }
        );
        println!(
            "  Require compat matrix:    {}",
            self.require_compatibility_matrix
        );
        println!("  Require hooks:            {}", self.require_hooks);
        println!("  Require key rotation:     {}", self.require_key_rotation);
        println!(
            "  Require cert chain:       {}",
            self.require_certificate_chain
        );
        if self.min_battery_override > 0 {
            println!("  Min battery override:     {}%", self.min_battery_override);
        }
        if !self.allowed_device_types.is_empty() {
            println!(
                "  Allowed device types:     {:?}",
                self.allowed_device_types
            );
        }
        if self.max_total_image_size > 0 {
            println!(
                "  Max total image size:     {} bytes",
                self.max_total_image_size
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{DeviceCompatibility, InstallHook, Partition, TargetSlot};
    use chrono::Utc;
    use std::collections::HashMap;

    fn base_manifest() -> OtaManifest {
        OtaManifest {
            manifest_version: 2,
            version: "2.0.0".into(),
            device_type: "gateway-v3".into(),
            partitions: vec![Partition {
                name: "rootfs".into(),
                hash_sha256: "aabb".into(),
                size: 1024,
                target_slot: TargetSlot::SlotA,
                delta: None,
            }],
            timestamp: Utc::now(),
            min_battery: 30,
            rollback_version: "1.0.0".into(),
            signature_algorithm: Some(KeyAlgorithm::Ed25519),
            key_rotation: None,
            certificate_chain: None,
            compatibility: Some(DeviceCompatibility {
                hardware_revisions: vec!["v3".into()],
                boot_rom_versions: vec!["1.2".into()],
            }),
            hooks: Some(vec![InstallHook {
                script: "check.sh".into(),
                hash_sha256: "aabb".into(),
                phase: "pre_install".into(),
            }]),
            dependencies: None,
            target_partition_size: None,
            required_free_space: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn default_policy_passes_basic_manifest() {
        let policy = VerificationPolicy::default();
        let manifest = base_manifest();
        let violations = policy.evaluate(&manifest);
        assert!(violations.is_empty(), "violations: {:?}", violations);
    }

    #[test]
    fn algorithm_mismatch_detected() {
        let policy = VerificationPolicy {
            require_algorithm: Some(KeyAlgorithm::RsaPss),
            ..Default::default()
        };
        let manifest = base_manifest();
        let violations = policy.evaluate(&manifest);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("algorithm"));
    }

    #[test]
    fn manifest_version_too_low() {
        let policy = VerificationPolicy {
            min_manifest_version: 2,
            ..Default::default()
        };
        let mut manifest = base_manifest();
        manifest.manifest_version = 1;
        let violations = policy.evaluate(&manifest);
        assert!(violations.iter().any(|v| v.contains("manifest_version")));
    }

    #[test]
    fn device_type_not_allowed() {
        let policy = VerificationPolicy {
            allowed_device_types: vec!["other-device".into()],
            ..Default::default()
        };
        let manifest = base_manifest();
        let violations = policy.evaluate(&manifest);
        assert!(violations.iter().any(|v| v.contains("device type")));
    }

    #[test]
    fn max_image_size_exceeded() {
        let policy = VerificationPolicy {
            max_total_image_size: 512,
            ..Default::default()
        };
        let manifest = base_manifest(); // has 1024 bytes
        let violations = policy.evaluate(&manifest);
        assert!(violations.iter().any(|v| v.contains("total image size")));
    }

    #[test]
    fn policy_roundtrip() {
        let policy = VerificationPolicy::strict_example();
        let json = policy.to_json().expect("serialize");
        let parsed = VerificationPolicy::from_json(&json).expect("parse");
        assert_eq!(parsed.name, policy.name);
        assert_eq!(parsed.max_age_hours, policy.max_age_hours);
    }

    #[test]
    fn policy_file_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("policy.json");
        let policy = VerificationPolicy::strict_example();
        policy.save(&path).expect("save");
        let loaded = VerificationPolicy::from_file(&path).expect("load");
        assert_eq!(loaded.name, policy.name);
    }

    #[test]
    fn battery_override_violation() {
        let policy = VerificationPolicy {
            min_battery_override: 50,
            ..Default::default()
        };
        let manifest = base_manifest(); // min_battery = 30
        let violations = policy.evaluate(&manifest);
        assert!(violations.iter().any(|v| v.contains("min_battery")));
    }
}
