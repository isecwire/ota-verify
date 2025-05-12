# Changelog

## [1.0.0] - 2026-04-03
### Added
- Stable release, production-ready
- Hardware attestation integration — verify TPM2 quote before accepting OTA
- Manifest template generator (manifest-template subcommand)
- Partition size validation against device profile database
- Support for compressed payloads (zstd, gzip) with transparent decompression verification
- Shell completions generation (--completions bash/zsh/fish)
### Changed
- Ed25519 is now the default algorithm (was unspecified)
- Audit log format includes machine-readable severity levels
- Batch mode now supports glob patterns
### Fixed
- ECDSA signature verification with DER-encoded signatures
- Policy file parsing with comments and empty lines
- Audit log file locking for concurrent verifications

## [0.2.0] - 2026-03-01
### Added
- RSA-PSS and ECDSA P-256 signature support
- Configurable verification policy engine (12 rules)
- Structured JSON audit logging with per-step timing
- Batch verification mode for directories of packages
- Colored terminal output with status indicators
- Certificate chain verification
- Device compatibility matrix in manifests
- Delta update metadata support
- Pre/post install hook hash verification
### Changed
- Manifest schema v2 with backward compatibility
- CLI expanded with info, policy subcommands

## [0.1.0] - 2025-12-22
### Added
- Initial release
- Ed25519 signature generation and verification
- OTA manifest creation and parsing (JSON)
- SHA-256 hash verification of partition files
- A/B partition rollback protection (version comparison)
- Manifest expiry checking
- Key generation (keygen subcommand)
- Manifest signing (sign subcommand)
