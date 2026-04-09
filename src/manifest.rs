use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::errors::{OtaError, Result};

/// Supported cryptographic algorithm identifiers used in manifests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    RsaPss,
    EcdsaP256,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Ed25519 => write!(f, "ed25519"),
            KeyAlgorithm::RsaPss => write!(f, "rsa_pss"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ecdsa_p256"),
        }
    }
}

/// Target slot in an A/B partition scheme.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetSlot {
    SlotA,
    SlotB,
    /// Written to both slots (e.g. bootloader).
    Both,
}

impl std::fmt::Display for TargetSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetSlot::SlotA => write!(f, "slot_a"),
            TargetSlot::SlotB => write!(f, "slot_b"),
            TargetSlot::Both => write!(f, "both"),
        }
    }
}

/// Patch algorithm for delta updates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchAlgorithm {
    Bsdiff,
    Zstd,
}

impl std::fmt::Display for PatchAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchAlgorithm::Bsdiff => write!(f, "bsdiff"),
            PatchAlgorithm::Zstd => write!(f, "zstd"),
        }
    }
}

/// Delta update metadata embedded in a partition entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaMetadata {
    /// Base version this delta is relative to.
    pub delta_base_version: String,
    /// Algorithm used to produce the patch.
    pub patch_algorithm: PatchAlgorithm,
}

/// A script hook that runs before or after installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallHook {
    /// Filename of the hook script inside the package directory.
    pub script: String,
    /// SHA-256 hash of the hook script (verified before execution).
    pub hash_sha256: String,
    /// Phase: "pre_install" or "post_install".
    pub phase: String,
}

/// Device hardware compatibility entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCompatibility {
    /// Compatible hardware revisions (e.g. ["v3", "v3.1"]).
    #[serde(default)]
    pub hardware_revisions: Vec<String>,
    /// Compatible boot ROM versions (e.g. ["1.2", "1.3"]).
    #[serde(default)]
    pub boot_rom_versions: Vec<String>,
}

/// Dependency on another update that must be installed first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDependency {
    /// The required update version.
    pub version: String,
    /// The device type / component this dependency applies to.
    pub component: String,
}

/// Key rotation metadata: advertise the next public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotation {
    /// Hex-encoded next public key.
    pub next_public_key: String,
    /// Algorithm of the next key.
    pub next_key_algorithm: KeyAlgorithm,
    /// Signature of the next public key by the current signing key, proving authorization.
    pub next_key_signature: String,
}

/// A single partition image included in the OTA package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    /// Partition name (e.g. "rootfs", "kernel", "bootloader").
    pub name: String,
    /// SHA-256 hash of the partition image file.
    pub hash_sha256: String,
    /// Size in bytes of the partition image.
    pub size: u64,
    /// Target slot for A/B partitioning.
    pub target_slot: TargetSlot,
    /// Optional delta update metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<DeltaMetadata>,
}

/// OTA update manifest describing the firmware package.
///
/// Supports both v1 (original) and v2 (extended) manifest formats.
/// V1 fields are always present; v2 fields are optional and default to None.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaManifest {
    // ---- schema versioning ----
    /// Manifest schema version. Defaults to 1 for backward compatibility.
    #[serde(default = "default_manifest_version")]
    pub manifest_version: u32,

    // ---- core v1 fields ----
    /// Semantic version of this update (e.g. "2.4.1").
    pub version: String,
    /// Device type this update targets (e.g. "isecwire-gateway-v3").
    pub device_type: String,
    /// List of partition images in this package.
    pub partitions: Vec<Partition>,
    /// Creation timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Minimum battery percentage required to apply the update.
    pub min_battery: u8,
    /// Minimum version that supports rollback from this update.
    pub rollback_version: String,

    // ---- v2 cryptographic fields ----
    /// Algorithm used to sign this manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<KeyAlgorithm>,

    /// Key rotation metadata for planned key transitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotation>,

    /// Certificate chain: list of hex-encoded certificates from signing cert to CA.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<String>>,

    // ---- v2 device compatibility ----
    /// Device hardware compatibility matrix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility: Option<DeviceCompatibility>,

    // ---- v2 install hooks ----
    /// Pre- and post-install hook scripts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Vec<InstallHook>>,

    // ---- v2 dependency chain ----
    /// Updates that must be installed before this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<UpdateDependency>>,

    // ---- v2 size constraints ----
    /// Target partition size in bytes (for size-fit verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_partition_size: Option<u64>,

    /// Required free space in bytes beyond the images themselves.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_free_space: Option<u64>,

    // ---- extensible metadata ----
    /// Arbitrary key-value metadata for custom extensions.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

fn default_manifest_version() -> u32 {
    1
}

impl OtaManifest {
    /// Load a manifest from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Self::from_json(&data)
    }

    /// Parse a manifest from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let manifest: Self =
            serde_json::from_str(json).map_err(|e| OtaError::ManifestParse(e.to_string()))?;
        manifest.validate_version()?;
        Ok(manifest)
    }

    /// Validate the manifest schema version is supported.
    fn validate_version(&self) -> Result<()> {
        match self.manifest_version {
            1 | 2 => Ok(()),
            v => Err(OtaError::ManifestVersionUnsupported(format!(
                "manifest_version {} is not supported (expected 1 or 2)",
                v
            ))),
        }
    }

    /// Returns true if this is a v2 manifest with extended fields.
    pub fn is_v2(&self) -> bool {
        self.manifest_version >= 2
    }

    /// Serialize the manifest to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| OtaError::ManifestParse(e.to_string()))
    }

    /// Serialize the manifest to canonical (compact) JSON for signing.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| OtaError::ManifestParse(e.to_string()))
    }

    /// Save the manifest to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Compute total image size across all partitions.
    pub fn total_image_size(&self) -> u64 {
        self.partitions.iter().map(|p| p.size).sum()
    }

    /// Return the effective signature algorithm, defaulting to Ed25519 for v1.
    pub fn effective_algorithm(&self) -> KeyAlgorithm {
        self.signature_algorithm
            .clone()
            .unwrap_or(KeyAlgorithm::Ed25519)
    }

    /// Print a human-readable summary of the manifest.
    pub fn print_summary(&self) {
        println!("OTA Manifest Summary");
        println!("====================");
        println!("Manifest version: v{}", self.manifest_version);
        println!("Version:          {}", self.version);
        println!("Device type:      {}", self.device_type);
        println!("Timestamp:        {}", self.timestamp);
        println!("Min battery:      {}%", self.min_battery);
        println!("Rollback version: {}", self.rollback_version);
        println!("Partitions:       {}", self.partitions.len());

        if let Some(ref algo) = self.signature_algorithm {
            println!("Signature algo:   {}", algo);
        }

        println!();
        for (i, p) in self.partitions.iter().enumerate() {
            println!("  [{}] {}", i + 1, p.name);
            println!("      Hash:   {}", p.hash_sha256);
            println!("      Size:   {} bytes", p.size);
            println!("      Slot:   {}", p.target_slot);
            if let Some(ref delta) = p.delta {
                println!(
                    "      Delta:  base={}, algo={}",
                    delta.delta_base_version, delta.patch_algorithm
                );
            }
        }

        if let Some(ref compat) = self.compatibility {
            println!();
            println!("Device Compatibility:");
            if !compat.hardware_revisions.is_empty() {
                println!(
                    "  Hardware revisions: {}",
                    compat.hardware_revisions.join(", ")
                );
            }
            if !compat.boot_rom_versions.is_empty() {
                println!(
                    "  Boot ROM versions:  {}",
                    compat.boot_rom_versions.join(", ")
                );
            }
        }

        if let Some(ref hooks) = self.hooks {
            println!();
            println!("Install Hooks:");
            for hook in hooks {
                println!("  [{}] {}", hook.phase, hook.script);
            }
        }

        if let Some(ref deps) = self.dependencies {
            if !deps.is_empty() {
                println!();
                println!("Dependencies:");
                for dep in deps {
                    println!("  {} >= {}", dep.component, dep.version);
                }
            }
        }

        if let Some(ref rotation) = self.key_rotation {
            println!();
            println!("Key Rotation:");
            println!("  Next key algo:  {}", rotation.next_key_algorithm);
            println!(
                "  Next public key: {}...",
                &rotation.next_public_key[..std::cmp::min(32, rotation.next_public_key.len())]
            );
        }

        if let Some(target_size) = self.target_partition_size {
            let total = self.total_image_size();
            println!();
            println!("Size Constraints:");
            println!("  Total image size:     {} bytes", total);
            println!("  Target partition:     {} bytes", target_size);
            if total <= target_size {
                println!("  Headroom:             {} bytes", target_size - total);
            } else {
                println!(
                    "  OVERFLOW:             {} bytes over limit",
                    total - target_size
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_manifest() -> OtaManifest {
        OtaManifest {
            manifest_version: 1,
            version: "2.4.1".into(),
            device_type: "isecwire-gateway-v3".into(),
            partitions: vec![
                Partition {
                    name: "rootfs".into(),
                    hash_sha256: "abcdef1234567890".into(),
                    size: 1024,
                    target_slot: TargetSlot::SlotA,
                    delta: None,
                },
                Partition {
                    name: "bootloader".into(),
                    hash_sha256: "0987654321fedcba".into(),
                    size: 512,
                    target_slot: TargetSlot::Both,
                    delta: None,
                },
            ],
            timestamp: Utc::now(),
            min_battery: 30,
            rollback_version: "2.3.0".into(),
            signature_algorithm: None,
            key_rotation: None,
            certificate_chain: None,
            compatibility: None,
            hooks: None,
            dependencies: None,
            target_partition_size: None,
            required_free_space: None,
            metadata: HashMap::new(),
        }
    }

    fn sample_v2_manifest() -> OtaManifest {
        let mut m = sample_manifest();
        m.manifest_version = 2;
        m.signature_algorithm = Some(KeyAlgorithm::Ed25519);
        m.compatibility = Some(DeviceCompatibility {
            hardware_revisions: vec!["v3".into(), "v3.1".into()],
            boot_rom_versions: vec!["1.2".into()],
        });
        m.hooks = Some(vec![InstallHook {
            script: "pre_check.sh".into(),
            hash_sha256: "aabbccdd".into(),
            phase: "pre_install".into(),
        }]);
        m.dependencies = Some(vec![UpdateDependency {
            version: "2.3.0".into(),
            component: "bootloader".into(),
        }]);
        m.target_partition_size = Some(100_000_000);
        m.required_free_space = Some(10_000_000);
        m.partitions[0].delta = Some(DeltaMetadata {
            delta_base_version: "2.3.0".into(),
            patch_algorithm: PatchAlgorithm::Bsdiff,
        });
        m
    }

    #[test]
    fn serialization_roundtrip() {
        let manifest = sample_manifest();
        let json = manifest.to_json().expect("serialize");
        let parsed = OtaManifest::from_json(&json).expect("deserialize");

        assert_eq!(parsed.version, manifest.version);
        assert_eq!(parsed.device_type, manifest.device_type);
        assert_eq!(parsed.partitions.len(), manifest.partitions.len());
        assert_eq!(parsed.partitions[0].name, "rootfs");
        assert_eq!(parsed.partitions[1].target_slot, TargetSlot::Both);
        assert_eq!(parsed.min_battery, manifest.min_battery);
        assert_eq!(parsed.rollback_version, manifest.rollback_version);
    }

    #[test]
    fn v2_serialization_roundtrip() {
        let manifest = sample_v2_manifest();
        let json = manifest.to_json().expect("serialize");
        let parsed = OtaManifest::from_json(&json).expect("deserialize");

        assert_eq!(parsed.manifest_version, 2);
        assert!(parsed.is_v2());
        assert_eq!(parsed.signature_algorithm, Some(KeyAlgorithm::Ed25519));
        assert!(parsed.compatibility.is_some());
        assert!(parsed.hooks.is_some());
        assert!(parsed.dependencies.is_some());
        assert_eq!(parsed.target_partition_size, Some(100_000_000));
        assert!(parsed.partitions[0].delta.is_some());
    }

    #[test]
    fn canonical_json_roundtrip() {
        let manifest = sample_manifest();
        let bytes = manifest.to_canonical_json().expect("canonical");
        let parsed: OtaManifest = serde_json::from_slice(&bytes).expect("parse canonical");
        assert_eq!(parsed.version, manifest.version);
        assert_eq!(parsed.partitions.len(), 2);
    }

    #[test]
    fn v1_manifest_defaults_version_to_1() {
        let json = r#"{
            "version": "1.0.0",
            "device_type": "test",
            "partitions": [],
            "timestamp": "2025-01-01T00:00:00Z",
            "min_battery": 20,
            "rollback_version": "0.9.0"
        }"#;
        let parsed = OtaManifest::from_json(json).expect("parse v1");
        assert_eq!(parsed.manifest_version, 1);
        assert!(!parsed.is_v2());
    }

    #[test]
    fn unsupported_manifest_version_rejected() {
        let json = r#"{
            "manifest_version": 99,
            "version": "1.0.0",
            "device_type": "test",
            "partitions": [],
            "timestamp": "2025-01-01T00:00:00Z",
            "min_battery": 20,
            "rollback_version": "0.9.0"
        }"#;
        let result = OtaManifest::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn total_image_size_computed() {
        let manifest = sample_manifest();
        assert_eq!(manifest.total_image_size(), 1024 + 512);
    }

    #[test]
    fn effective_algorithm_defaults_to_ed25519() {
        let manifest = sample_manifest();
        assert_eq!(manifest.effective_algorithm(), KeyAlgorithm::Ed25519);
    }

    #[test]
    fn invalid_manifest_missing_version() {
        let json = r#"{
            "device_type": "test",
            "partitions": [],
            "timestamp": "2025-01-01T00:00:00Z",
            "min_battery": 20,
            "rollback_version": "1.0.0"
        }"#;
        let result = OtaManifest::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_manifest_missing_partitions() {
        let json = r#"{
            "version": "1.0.0",
            "device_type": "test",
            "timestamp": "2025-01-01T00:00:00Z",
            "min_battery": 20,
            "rollback_version": "0.9.0"
        }"#;
        let result = OtaManifest::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_manifest_missing_timestamp() {
        let json = r#"{
            "version": "1.0.0",
            "device_type": "test",
            "partitions": [],
            "min_battery": 20,
            "rollback_version": "0.9.0"
        }"#;
        let result = OtaManifest::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_manifest_garbage_input() {
        let result = OtaManifest::from_json("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn target_slot_serde_snake_case() {
        let slot_a: TargetSlot = serde_json::from_str(r#""slot_a""#).unwrap();
        assert_eq!(slot_a, TargetSlot::SlotA);

        let slot_b: TargetSlot = serde_json::from_str(r#""slot_b""#).unwrap();
        assert_eq!(slot_b, TargetSlot::SlotB);

        let both: TargetSlot = serde_json::from_str(r#""both""#).unwrap();
        assert_eq!(both, TargetSlot::Both);
    }

    #[test]
    fn target_slot_invalid_value() {
        let result: std::result::Result<TargetSlot, _> = serde_json::from_str(r#""slot_c""#);
        assert!(result.is_err());
    }

    #[test]
    fn target_slot_display() {
        assert_eq!(TargetSlot::SlotA.to_string(), "slot_a");
        assert_eq!(TargetSlot::SlotB.to_string(), "slot_b");
        assert_eq!(TargetSlot::Both.to_string(), "both");
    }

    #[test]
    fn key_algorithm_display() {
        assert_eq!(KeyAlgorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(KeyAlgorithm::RsaPss.to_string(), "rsa_pss");
        assert_eq!(KeyAlgorithm::EcdsaP256.to_string(), "ecdsa_p256");
    }

    #[test]
    fn patch_algorithm_display() {
        assert_eq!(PatchAlgorithm::Bsdiff.to_string(), "bsdiff");
        assert_eq!(PatchAlgorithm::Zstd.to_string(), "zstd");
    }

    #[test]
    fn file_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("manifest.json");

        let manifest = sample_manifest();
        manifest.save(&path).expect("save");

        let loaded = OtaManifest::from_file(&path).expect("load");
        assert_eq!(loaded.version, manifest.version);
        assert_eq!(loaded.device_type, manifest.device_type);
        assert_eq!(loaded.partitions.len(), manifest.partitions.len());
    }
}
