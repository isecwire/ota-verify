//! Audit logging for OTA verification.
//!
//! Produces a structured JSON audit log recording every verification step,
//! its outcome, and timing. Designed for post-incident forensics and
//! compliance evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::errors::Result;

/// Outcome of a single verification step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Pass,
    Fail,
    Skip,
}

impl std::fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepOutcome::Pass => write!(f, "PASS"),
            StepOutcome::Fail => write!(f, "FAIL"),
            StepOutcome::Skip => write!(f, "SKIP"),
        }
    }
}

/// A single audit log entry for one verification step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStep {
    /// Name of the verification step.
    pub step: String,
    /// Outcome of the step.
    pub outcome: StepOutcome,
    /// Human-readable detail message.
    pub detail: String,
    /// Timestamp when the step completed.
    pub timestamp: DateTime<Utc>,
    /// Duration of the step in milliseconds.
    pub duration_ms: u64,
}

/// Complete audit log for one verification run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Unique run identifier.
    pub run_id: String,
    /// Manifest file path that was verified.
    pub manifest_path: String,
    /// Package version from the manifest.
    pub package_version: String,
    /// Device type from the manifest.
    pub device_type: String,
    /// Overall verification result.
    pub overall_result: StepOutcome,
    /// When the verification run started.
    pub started_at: DateTime<Utc>,
    /// When the verification run completed.
    pub completed_at: DateTime<Utc>,
    /// Total duration in milliseconds.
    pub total_duration_ms: u64,
    /// Individual verification steps.
    pub steps: Vec<AuditStep>,
}

impl AuditLog {
    /// Create a new audit log for a verification run.
    pub fn new(manifest_path: &str, package_version: &str, device_type: &str) -> Self {
        Self {
            run_id: uuid::Uuid::new_v4().to_string(),
            manifest_path: manifest_path.into(),
            package_version: package_version.into(),
            device_type: device_type.into(),
            overall_result: StepOutcome::Pass,
            started_at: Utc::now(),
            completed_at: Utc::now(),
            total_duration_ms: 0,
            steps: Vec::new(),
        }
    }

    /// Record a verification step.
    pub fn record_step(
        &mut self,
        step: &str,
        outcome: StepOutcome,
        detail: &str,
        duration_ms: u64,
    ) {
        if outcome == StepOutcome::Fail {
            self.overall_result = StepOutcome::Fail;
        }

        self.steps.push(AuditStep {
            step: step.into(),
            outcome,
            detail: detail.into(),
            timestamp: Utc::now(),
            duration_ms,
        });
    }

    /// Finalize the audit log with completion time.
    pub fn finalize(&mut self) {
        self.completed_at = Utc::now();
        self.total_duration_ms = (self.completed_at - self.started_at)
            .num_milliseconds()
            .max(0) as u64;
    }

    /// Serialize the audit log to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Save the audit log to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Return the count of passed, failed, and skipped steps.
    pub fn summary(&self) -> (usize, usize, usize) {
        let pass = self.steps.iter().filter(|s| s.outcome == StepOutcome::Pass).count();
        let fail = self.steps.iter().filter(|s| s.outcome == StepOutcome::Fail).count();
        let skip = self.steps.iter().filter(|s| s.outcome == StepOutcome::Skip).count();
        (pass, fail, skip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_records_steps() {
        let mut log = AuditLog::new("manifest.json", "2.0.0", "gateway");
        log.record_step("signature", StepOutcome::Pass, "valid", 10);
        log.record_step("hashes", StepOutcome::Pass, "all match", 50);
        log.finalize();

        assert_eq!(log.steps.len(), 2);
        assert_eq!(log.overall_result, StepOutcome::Pass);
        let (pass, fail, skip) = log.summary();
        assert_eq!(pass, 2);
        assert_eq!(fail, 0);
        assert_eq!(skip, 0);
    }

    #[test]
    fn audit_log_failure_sets_overall() {
        let mut log = AuditLog::new("manifest.json", "2.0.0", "gateway");
        log.record_step("signature", StepOutcome::Pass, "valid", 10);
        log.record_step("hashes", StepOutcome::Fail, "mismatch on rootfs", 50);
        log.finalize();

        assert_eq!(log.overall_result, StepOutcome::Fail);
    }

    #[test]
    fn audit_log_json_roundtrip() {
        let mut log = AuditLog::new("manifest.json", "2.0.0", "gateway");
        log.record_step("signature", StepOutcome::Pass, "valid", 10);
        log.finalize();

        let json = log.to_json().expect("serialize");
        let parsed: AuditLog = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.run_id, log.run_id);
        assert_eq!(parsed.steps.len(), 1);
    }

    #[test]
    fn audit_log_file_save() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("audit.json");

        let mut log = AuditLog::new("manifest.json", "2.0.0", "gateway");
        log.record_step("test", StepOutcome::Pass, "ok", 5);
        log.finalize();
        log.save(&path).expect("save");

        let data = std::fs::read_to_string(&path).expect("read");
        assert!(data.contains("run_id"));
        assert!(data.contains("test"));
    }

    #[test]
    fn step_outcome_display() {
        assert_eq!(StepOutcome::Pass.to_string(), "PASS");
        assert_eq!(StepOutcome::Fail.to_string(), "FAIL");
        assert_eq!(StepOutcome::Skip.to_string(), "SKIP");
    }
}
