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
                println!("      Delta:  base={}, algo={}", delta.delta_base_version, delta.patch_algorithm);
            }
        }

        if let Some(ref compat) = self.compatibility {
            println!();
            println!("Device Compatibility:");
            if !compat.hardware_revisions.is_empty() {
                println!("  Hardware revisions: {}", compat.hardware_revisions.join(", "));
            }
            if !compat.boot_rom_versions.is_empty() {
                println!("  Boot ROM versions:  {}", compat.boot_rom_versions.join(", "));
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
            println!("  Next public key: {}...", &rotation.next_public_key[..std::cmp::min(32, rotation.next_public_key.len())]);
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
                println!("  OVERFLOW:             {} bytes over limit", total - target_size);
            }
        }
    }
}

