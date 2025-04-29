//! Colored terminal output for OTA verification results.
//!
//! Provides formatted, color-coded output for verification reports,
//! info displays, and policy summaries.

use colored::Colorize;

use crate::audit::{AuditLog, StepOutcome};
use crate::manifest::OtaManifest;
use crate::policy::VerificationPolicy;

/// Print a verification report with colored status indicators.
pub fn print_verification_report(checks: &[String], manifest: &OtaManifest) {
    println!();
    println!(
        "{}",
        "OTA Package Verification: PASSED"
            .green()
            .bold()
    );
    println!();
    for check in checks {
        println!("  {} {}", "\u{2713}".green().bold(), check);
    }
    println!();
    println!(
        "Package {} for {} is valid and ready for deployment.",
        manifest.version.cyan().bold(),
        manifest.device_type.cyan()
    );
}

/// Print a verification failure report.
pub fn print_verification_failure(error: &str) {
    println!();
    println!(
        "{}",
        "OTA Package Verification: FAILED"
            .red()
            .bold()
    );
    println!();
    println!("  {} {}", "\u{2717}".red().bold(), error);
}

/// Print policy violations.
pub fn print_policy_violations(violations: &[String]) {
    println!();
    println!(
        "{}",
        "Policy Evaluation: FAILED".red().bold()
    );
    println!();
    for v in violations {
        println!("  {} {}", "\u{2717}".red().bold(), v);
    }
}

/// Print policy pass.
pub fn print_policy_pass(policy_name: &str) {
    println!(
        "  {} Policy '{}' satisfied",
        "\u{2713}".green().bold(),
        policy_name.cyan()
    );
}

/// Print a detailed info table for a manifest.
pub fn print_manifest_info(manifest: &OtaManifest) {
    let sep = "=".repeat(60);

    println!();
    println!("{}", "OTA Manifest Analysis".cyan().bold());
    println!("{}", sep.dimmed());
    println!();

    // Core fields table
    print_field("Manifest version", &format!("v{}", manifest.manifest_version));
    print_field("Package version", &manifest.version);
    print_field("Device type", &manifest.device_type);
    print_field("Timestamp", &manifest.timestamp.to_rfc3339());
    print_field("Min battery", &format!("{}%", manifest.min_battery));
    print_field("Rollback version", &manifest.rollback_version);
    print_field("Signature algorithm", &manifest.effective_algorithm().to_string());
    print_field("Total image size", &format_bytes(manifest.total_image_size()));
    print_field("Partition count", &manifest.partitions.len().to_string());

    // Partitions
    println!();
    println!("{}", "Partitions".yellow().bold());
    println!("{}", "-".repeat(60).dimmed());
    for (i, p) in manifest.partitions.iter().enumerate() {
        println!(
            "  {}. {} {} {} {}",
            (i + 1).to_string().white().bold(),
            p.name.cyan(),
            format!("({})", format_bytes(p.size)).dimmed(),
            "->".dimmed(),
            p.target_slot.to_string().yellow()
        );
        println!("     hash: {}", truncate_hash(&p.hash_sha256).dimmed());
        if let Some(ref delta) = p.delta {
            println!(
                "     delta: base={}, algo={}",
                delta.delta_base_version.yellow(),
                delta.patch_algorithm.to_string().yellow()
            );
        }
    }

    // Compatibility
    if let Some(ref compat) = manifest.compatibility {
        println!();
        println!("{}", "Device Compatibility".yellow().bold());
        println!("{}", "-".repeat(60).dimmed());
        if !compat.hardware_revisions.is_empty() {
            print_field("Hardware revisions", &compat.hardware_revisions.join(", "));
        }
        if !compat.boot_rom_versions.is_empty() {
            print_field("Boot ROM versions", &compat.boot_rom_versions.join(", "));
        }
    }

    // Hooks
    if let Some(ref hooks) = manifest.hooks {
        if !hooks.is_empty() {
            println!();
            println!("{}", "Install Hooks".yellow().bold());
            println!("{}", "-".repeat(60).dimmed());
            for hook in hooks {
                println!(
                    "  [{}] {}",
                    hook.phase.cyan(),
                    hook.script
                );
            }
        }
    }

    // Dependencies
    if let Some(ref deps) = manifest.dependencies {
        if !deps.is_empty() {
            println!();
            println!("{}", "Dependencies".yellow().bold());
            println!("{}", "-".repeat(60).dimmed());
            for dep in deps {
                println!(
                    "  {} >= {}",
                    dep.component.cyan(),
                    dep.version.yellow()
                );
            }
        }
    }

    // Key rotation
    if let Some(ref rotation) = manifest.key_rotation {
        println!();
        println!("{}", "Key Rotation".yellow().bold());
        println!("{}", "-".repeat(60).dimmed());
        print_field("Next key algorithm", &rotation.next_key_algorithm.to_string());
        print_field(
            "Next public key",
            &format!(
                "{}...",
                &rotation.next_public_key[..std::cmp::min(32, rotation.next_public_key.len())]
            ),
        );
    }

    // Size constraints
    if let Some(target_size) = manifest.target_partition_size {
        let total = manifest.total_image_size();
        println!();
        println!("{}", "Size Constraints".yellow().bold());
        println!("{}", "-".repeat(60).dimmed());
        print_field("Total image size", &format_bytes(total));
        print_field("Target partition", &format_bytes(target_size));
        if total <= target_size {
            print_field(
                "Headroom",
                &format!("{} {}", format_bytes(target_size - total), "\u{2713}".green()),
            );
        } else {
            print_field(
                "OVERFLOW",
                &format!(
                    "{} over limit {}",
                    format_bytes(total - target_size),
                    "\u{2717}".red()
                ),
            );
        }
    }

    // Metadata
    if !manifest.metadata.is_empty() {
        println!();
        println!("{}", "Metadata".yellow().bold());
        println!("{}", "-".repeat(60).dimmed());
        for (k, v) in &manifest.metadata {
            print_field(k, v);
        }
    }

    println!();
}

/// Print an audit log summary with colors.
pub fn print_audit_summary(audit: &AuditLog) {
    let (pass, fail, skip) = audit.summary();

    println!();
    let title = if audit.overall_result == StepOutcome::Pass {
        "Audit Summary: PASS".green().bold()
    } else {
        "Audit Summary: FAIL".red().bold()
    };
    println!("{}", title);
    println!("{}", "-".repeat(50).dimmed());
    println!("  Run ID:     {}", audit.run_id.dimmed());
    println!("  Duration:   {}ms", audit.total_duration_ms);
    println!(
        "  Steps:      {} passed, {} failed, {} skipped",
        pass.to_string().green(),
        fail.to_string().red(),
        skip.to_string().yellow()
    );
    println!();

    for step in &audit.steps {
        let icon = match step.outcome {
            StepOutcome::Pass => "\u{2713}".green().bold(),
            StepOutcome::Fail => "\u{2717}".red().bold(),
            StepOutcome::Skip => "\u{26a0}".yellow().bold(),
        };
        println!(
            "  {} {} ({}ms) {}",
            icon,
            step.step.white(),
            step.duration_ms,
            step.detail.dimmed()
        );
    }
}

/// Print batch verification summary.
pub fn print_batch_summary(results: &[(String, bool, String)]) {
    println!();
    println!("{}", "Batch Verification Summary".cyan().bold());
    println!("{}", "=".repeat(60).dimmed());
    println!();

    let total = results.len();
    let passed = results.iter().filter(|(_, ok, _)| *ok).count();
    let failed = total - passed;

    for (name, ok, detail) in results {
        let icon = if *ok {
            "\u{2713}".green().bold()
        } else {
            "\u{2717}".red().bold()
        };
        println!("  {} {} {}", icon, name.white(), detail.dimmed());
    }

    println!();
    println!(
        "  Total: {}  Passed: {}  Failed: {}",
        total,
        passed.to_string().green().bold(),
        failed.to_string().red().bold()
    );
}

/// Print a formatted policy summary with colors.
pub fn print_policy_info(policy: &VerificationPolicy) {
    println!();
    println!(
        "{} {}",
        "Verification Policy:".cyan().bold(),
        policy.name.white().bold()
    );
    println!("{}", "=".repeat(60).dimmed());
    println!();

    print_field(
        "Required algorithm",
        &policy.require_algorithm.as_ref().map(|a| a.to_string()).unwrap_or("any".into()),
    );
    print_field(
        "Max age (hours)",
        &if policy.max_age_hours == 0 {
            "unlimited".into()
        } else {
            policy.max_age_hours.to_string()
        },
    );
    print_field("Rollback protection", &policy.require_rollback_protection.to_string());
    print_field(
        "Min manifest version",
        &if policy.min_manifest_version == 0 {
            "any".into()
        } else {
            format!("v{}", policy.min_manifest_version)
        },
    );
    print_field("Require compat matrix", &policy.require_compatibility_matrix.to_string());
    print_field("Require hooks", &policy.require_hooks.to_string());
    print_field("Require key rotation", &policy.require_key_rotation.to_string());
    print_field("Require cert chain", &policy.require_certificate_chain.to_string());

    if policy.min_battery_override > 0 {
        print_field("Min battery override", &format!("{}%", policy.min_battery_override));
    }
    if !policy.allowed_device_types.is_empty() {
        print_field("Allowed device types", &policy.allowed_device_types.join(", "));
    }
    if policy.max_total_image_size > 0 {
        print_field("Max total image size", &format_bytes(policy.max_total_image_size));
    }

    println!();
}

// --- Helpers ---

fn print_field(label: &str, value: &str) {
    println!(
        "  {:<24} {}",
        format!("{}:", label).dimmed(),
        value
    );
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn truncate_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 8..])
    } else {
        hash.to_string()
    }
}

