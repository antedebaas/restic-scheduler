//! Filesystem sandboxing using Linux Landlock LSM
//!
//! This module provides security sandboxing by restricting filesystem access to only
//! the paths required for restic-scheduler operation. It uses Linux's Landlock security
//! module (available since kernel 5.13) to create a secure sandbox.
//!
//! # Features
//!
//! - Automatic restriction of filesystem access based on configuration
//! - Read-write access to stats directory
//! - Read-only access to backup paths
//! - Execute access to notification and pre-backup commands
//! - Graceful degradation on systems without Landlock support
//!
//! # Security Model
//!
//! The sandboxing is applied after loading the configuration but before executing
//! any backup operations. This ensures that:
//!
//! 1. Configuration can be read from disk
//! 2. All subsequent operations are restricted to configured paths only
//! 3. Even if vulnerabilities exist, filesystem access remains limited
//!
//! # Kernel Support
//!
//! - **Required**: Linux kernel 5.13 or later with Landlock enabled
//! - **Fallback**: If Landlock is unavailable, operations continue without restrictions
//! - **Detection**: Automatically detects kernel support at runtime
//!
//! # Feature Flag
//!
//! This module is controlled by the `sandboxing` feature flag (enabled by default).
//! To disable sandboxing at compile time:
//!
//! ```bash
//! cargo build --no-default-features
//! ```

#[cfg(feature = "sandboxing")]
use anyhow::{Context, Result};
#[cfg(feature = "sandboxing")]
use landlock::{
    Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};
#[cfg(feature = "sandboxing")]
use std::collections::HashSet;
#[cfg(feature = "sandboxing")]
use std::path::{Path, PathBuf};
#[cfg(feature = "sandboxing")]
use tracing::{debug, info, warn};

use crate::config::Config;

/// Apply landlock sandboxing based on configuration paths
///
/// This function restricts filesystem access to only the paths needed by the application:
/// - Read-write access to stats_dir
/// - Read-only access to backup_paths
/// - Execute access to notification commands
/// - Execute access to pre-backup commands
///
/// The function will gracefully handle cases where landlock is not supported by the kernel.
#[cfg(feature = "sandboxing")]
pub fn apply_landlock_restrictions(config: &Config) -> Result<()> {
    // Use the highest ABI version available (V3 for landlock 0.3.x)
    let abi = ABI::V3;

    debug!("Applying landlock restrictions using ABI version V3");

    // Collect all paths that need access
    let mut read_only_paths = HashSet::new();
    let mut read_write_paths = HashSet::new();
    let mut execute_paths = HashSet::new();

    // Add stats directory with read-write access
    if let Some(stats_dir) = &config.global.stats_dir {
        if stats_dir.exists() {
            read_write_paths.insert(stats_dir.clone());
            debug!(
                "Adding read-write access to stats_dir: {}",
                stats_dir.display()
            );
        } else {
            warn!("Stats directory does not exist: {}", stats_dir.display());
        }
    }

    // Add backup paths with read-only access for all profiles
    for (profile_name, profile) in &config.profiles {
        for backup_path in &profile.backup_paths {
            if backup_path.exists() {
                read_only_paths.insert(backup_path.clone());
                debug!(
                    "Adding read-only access to backup path for profile '{}': {}",
                    profile_name,
                    backup_path.display()
                );
            } else {
                warn!(
                    "Backup path does not exist for profile '{}': {}",
                    profile_name,
                    backup_path.display()
                );
            }
        }

        // Add notification command paths with execute access
        if let Some(command_config) = &profile.notifications.command {
            let command_path = PathBuf::from(&command_config.command);

            // Only allow absolute paths for security
            if command_path.is_absolute() {
                if command_path.exists() {
                    execute_paths.insert(command_path.clone());
                    debug!(
                        "Adding execute access to notification command for profile '{}': {}",
                        profile_name,
                        command_path.display()
                    );
                } else {
                    warn!(
                        "Notification command does not exist for profile '{}': {}",
                        profile_name,
                        command_path.display()
                    );
                }
            } else {
                // For non-absolute paths, try to find in PATH
                if let Some(resolved_path) = find_command_in_path(&command_config.command) {
                    execute_paths.insert(resolved_path.clone());
                    debug!(
                        "Adding execute access to notification command for profile '{}': {}",
                        profile_name,
                        resolved_path.display()
                    );
                } else {
                    debug!(
                        "Could not resolve notification command for profile '{}': {}",
                        profile_name, command_config.command
                    );
                }
            }
        }

        // Add pre-backup command paths with execute access
        if let Some(pre_backup_cmd) = &profile.pre_backup_command {
            let parts: Vec<&str> = pre_backup_cmd.split_whitespace().collect();
            if let Some(cmd) = parts.first() {
                let command_path = PathBuf::from(cmd);

                if command_path.is_absolute() {
                    if command_path.exists() {
                        execute_paths.insert(command_path.clone());
                        debug!(
                            "Adding execute access to pre-backup command for profile '{}': {}",
                            profile_name,
                            command_path.display()
                        );
                    }
                } else if let Some(resolved_path) = find_command_in_path(cmd) {
                    execute_paths.insert(resolved_path.clone());
                    debug!(
                        "Adding execute access to pre-backup command for profile '{}': {}",
                        profile_name,
                        resolved_path.display()
                    );
                }
            }
        }
    }

    // Add common system paths needed for basic operations
    add_system_paths(&mut read_only_paths, &mut execute_paths);

    // Find and add restic binary
    if let Some(restic_path) = find_command_in_path("restic") {
        execute_paths.insert(restic_path.clone());
        debug!(
            "Adding execute access to restic binary: {}",
            restic_path.display()
        );
    } else {
        warn!("Could not find restic binary in PATH");
    }

    // Create the ruleset
    let status = create_and_apply_ruleset(abi, &read_only_paths, &read_write_paths, &execute_paths)
        .context("Failed to create and apply landlock ruleset")?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("Landlock restrictions fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            warn!("Landlock restrictions partially enforced (some rules may not be active)");
        }
        RulesetStatus::NotEnforced => {
            info!("Landlock is not supported by the kernel, skipping sandboxing");
        }
    }

    Ok(())
}

/// No-op version when sandboxing feature is disabled
///
/// This function is compiled when the `sandboxing` feature is disabled.
/// It does nothing and always returns success, allowing the application
/// to compile and run without Landlock dependencies.
#[cfg(not(feature = "sandboxing"))]
pub fn apply_landlock_restrictions(_config: &Config) -> anyhow::Result<()> {
    Ok(())
}

/// Create and apply the landlock ruleset
#[cfg(feature = "sandboxing")]
fn create_and_apply_ruleset(
    abi: ABI,
    read_only_paths: &HashSet<PathBuf>,
    read_write_paths: &HashSet<PathBuf>,
    execute_paths: &HashSet<PathBuf>,
) -> Result<landlock::RestrictionStatus> {
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    // Add read-only paths
    for path in read_only_paths {
        if let Err(e) = add_path_rule(&mut ruleset, path, AccessFs::from_read(abi)) {
            debug!("Could not add read-only rule for {}: {}", path.display(), e);
        }
    }

    // Add read-write paths
    for path in read_write_paths {
        if let Err(e) = add_path_rule(&mut ruleset, path, AccessFs::from_all(abi)) {
            debug!(
                "Could not add read-write rule for {}: {}",
                path.display(),
                e
            );
        }
    }

    // Add execute paths
    for path in execute_paths {
        if let Err(e) = add_path_rule(&mut ruleset, path, AccessFs::Execute.into()) {
            debug!("Could not add execute rule for {}: {}", path.display(), e);
        }
    }

    // Restrict the calling thread
    let status = ruleset.restrict_self()?;

    Ok(status)
}

/// Add a path rule to the ruleset
#[cfg(feature = "sandboxing")]
fn add_path_rule(
    ruleset: &mut landlock::RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<()> {
    let path_fd = PathFd::new(path)?;
    let rule = PathBeneath::new(path_fd, access);
    ruleset.add_rule(rule)?;
    Ok(())
}

/// Add common system paths that might be needed
#[cfg(feature = "sandboxing")]
fn add_system_paths(read_only_paths: &mut HashSet<PathBuf>, execute_paths: &mut HashSet<PathBuf>) {
    // Common binary directories - need both read and execute
    let bin_paths = vec![
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
        PathBuf::from("/usr/local/bin"),
    ];

    for path in bin_paths {
        if path.exists() {
            execute_paths.insert(path.clone());
            read_only_paths.insert(path);
        }
    }

    // Common library directories (needed for dynamic linking)
    let lib_paths = vec![
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib64"),
    ];

    for path in lib_paths {
        if path.exists() {
            read_only_paths.insert(path);
        }
    }

    // System directories that might be needed
    let system_paths = vec![
        PathBuf::from("/etc"),
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ];

    for path in system_paths {
        if path.exists() {
            read_only_paths.insert(path);
        }
    }

    // Temporary directory
    if let Ok(tmp_dir) = std::env::temp_dir().canonicalize() {
        read_only_paths.insert(tmp_dir);
    }
}

/// Find a command in the system PATH
#[cfg(feature = "sandboxing")]
fn find_command_in_path(command: &str) -> Option<PathBuf> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let mut cmd_path = PathBuf::from(dir);
            cmd_path.push(command);

            if cmd_path.exists() && cmd_path.is_file() {
                return Some(cmd_path);
            }
        }
    }
    None
}

#[cfg(all(test, feature = "sandboxing"))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_find_command_in_path() {
        // This should find a common system command
        let ls_path = find_command_in_path("ls");
        assert!(ls_path.is_some());

        // This should not find a non-existent command
        let fake_path = find_command_in_path("this-command-definitely-does-not-exist");
        assert!(fake_path.is_none());
    }

    #[test]
    fn test_apply_landlock_with_empty_config() {
        use crate::config::{Config, GlobalConfig};

        let config = Config {
            global: GlobalConfig {
                verbosity_level: 0,
                stats_dir: None,
                log_rotation: Default::default(),
            },
            profiles: HashMap::new(),
        };

        // This should not panic even with empty config
        // It might not be fully enforced if landlock is not available
        let result = apply_landlock_restrictions(&config);
        assert!(result.is_ok());
    }
}
