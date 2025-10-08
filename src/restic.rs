use anyhow::{Context, Result};
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::process::Command as AsyncCommand;
use tracing::{debug, info, warn};

use crate::config::{BackupStats, ProfileConfig, RetentionPolicy};

#[derive(Debug, Clone)]
pub struct ResticCommand {
    pub repository: String,
    pub env_vars: HashMap<String, String>,
    pub verbosity: u8,
}

#[derive(Debug, Clone)]
pub struct BackupResult {
    pub success: bool,
    pub stats: Option<BackupStats>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
}

impl ResticCommand {
    pub fn new(profile: &ProfileConfig) -> Self {
        Self {
            repository: profile.repository.clone(),
            env_vars: profile.get_env_vars(),
            verbosity: 0, // Will be set from global config
        }
    }

    pub fn with_verbosity(mut self, level: u8) -> Self {
        self.verbosity = level;
        self
    }

    /// Check if restic is available in PATH
    pub async fn check_restic_available() -> Result<String> {
        let output = AsyncCommand::new("restic")
            .arg("version")
            .output()
            .await
            .context("Failed to execute restic command. Is restic installed and in PATH?")?;

        if !output.status.success() {
            anyhow::bail!(
                "Restic command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let version = String::from_utf8_lossy(&output.stdout);
        Ok(version.trim().to_string())
    }

    /// Initialize a new restic repository
    pub async fn init_repository(&self, password: &str) -> Result<()> {
        info!("Initializing restic repository: {}", self.repository);

        let mut cmd = self.base_command_with_password(password);
        cmd.arg("init");

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic init command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to initialize repository: {}", error);
        }

        info!("Repository initialized successfully");
        Ok(())
    }

    /// Unlock the repository (remove stale locks)
    pub async fn unlock(&self, password: &str) -> Result<()> {
        debug!("Unlocking repository");

        let mut cmd = self.base_command_with_password(password);
        cmd.arg("unlock");

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic unlock command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to unlock repository: {}", error);
        } else {
            debug!("Repository unlocked successfully");
        }

        Ok(())
    }

    /// Perform a backup
    pub async fn backup(
        &self,
        password: &str,
        paths: &[PathBuf],
        tags: &[String],
        exclude_patterns: &[String],
        extra_args: &[String],
        one_file_system: bool,
    ) -> Result<BackupResult> {
        info!("Starting backup with tags: {:?}", tags);
        let start_time = Utc::now();

        let mut cmd = self.base_command_with_password(password);
        cmd.arg("backup");

        // Add verbosity
        if self.verbosity > 0 {
            cmd.arg(format!("--verbose={}", self.verbosity));
        }

        // Add tags
        for tag in tags {
            cmd.arg("--tag").arg(tag);
        }

        // Add one-file-system option (not supported on Windows)
        if one_file_system && !cfg!(windows) {
            cmd.arg("--one-file-system");
        }

        // Add exclude patterns
        for pattern in exclude_patterns {
            cmd.arg("--exclude").arg(pattern);
        }

        // Check for path-specific exclude files
        for path in paths {
            let exclude_path = path.join(".backup_exclude.txt");
            if exclude_path.exists() {
                cmd.arg("--exclude-file").arg(&exclude_path);
            }
        }

        // Add extra arguments
        for arg in extra_args {
            cmd.args(shellwords::split(arg).context("Failed to parse extra arguments")?);
        }

        // Add B2 connections if configured
        if let Some(connections) = self.env_vars.get("B2_CONNECTIONS") {
            cmd.arg("--option")
                .arg(format!("b2.connections={}", connections));
        }

        // Add backup paths
        for path in paths {
            cmd.arg(path);
        }

        debug!("Executing backup command: {:?}", cmd);

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic backup command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined_output = format!("{}\n{}", stdout, stderr).trim().to_string();

        let success = output.status.success();
        let snapshot_id = if success {
            self.extract_snapshot_id(&combined_output)
        } else {
            None
        };

        let duration = (Utc::now() - start_time).num_seconds() as u64;

        let stats = if success {
            if let Some(ref id) = snapshot_id {
                match self.get_backup_stats(password, tags, id, duration).await {
                    Ok(stats) => Some(stats),
                    Err(e) => {
                        warn!("Failed to get backup stats: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let result = BackupResult {
            success,
            stats,
            error: if success {
                None
            } else {
                Some(stderr.to_string())
            },
        };

        if success {
            info!("Backup completed successfully");
            if let Some(ref stats) = result.stats {
                info!(
                    "Backup stats - Added: {}, Removed: {}, Total: {}",
                    stats.added_size, stats.removed_size, stats.total_size
                );
            }
        } else {
            warn!("Backup failed: {}", stderr);
        }

        Ok(result)
    }

    /// Forget old snapshots according to retention policy
    pub async fn forget(
        &self,
        password: &str,
        tags: &[String],
        retention: &RetentionPolicy,
    ) -> Result<()> {
        info!("Cleaning up old snapshots according to retention policy");

        let mut cmd = self.base_command_with_password(password);
        cmd.arg("forget");

        if self.verbosity > 0 {
            cmd.arg(format!("--verbose={}", self.verbosity));
        }

        for tag in tags {
            cmd.arg("--tag").arg(tag);
        }
        cmd.arg("--prune");
        cmd.arg("--group-by").arg("paths,tags");

        if retention.hours > 0 {
            cmd.arg("--keep-hourly").arg(retention.hours.to_string());
        }
        if retention.days > 0 {
            cmd.arg("--keep-daily").arg(retention.days.to_string());
        }
        if retention.weeks > 0 {
            cmd.arg("--keep-weekly").arg(retention.weeks.to_string());
        }
        if retention.months > 0 {
            cmd.arg("--keep-monthly").arg(retention.months.to_string());
        }
        if retention.years > 0 {
            cmd.arg("--keep-yearly").arg(retention.years.to_string());
        }

        // Add B2 connections if configured
        if let Some(connections) = self.env_vars.get("B2_CONNECTIONS") {
            cmd.arg("--option")
                .arg(format!("b2.connections={}", connections));
        }

        debug!("Executing forget command: {:?}", cmd);

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic forget command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to clean up old snapshots: {}", error);
        }

        info!("Old snapshots cleaned up successfully");
        Ok(())
    }

    /// Check repository for errors
    pub async fn check(&self, password: &str, extra_args: &[String]) -> Result<CheckResult> {
        info!("Checking repository for errors");

        let mut cmd = self.base_command_with_password(password);
        cmd.arg("check");

        if self.verbosity > 0 {
            cmd.arg(format!("--verbose={}", self.verbosity));
        }

        // Add B2 connections if configured
        if let Some(connections) = self.env_vars.get("B2_CONNECTIONS") {
            cmd.arg("--option")
                .arg(format!("b2.connections={}", connections));
        }

        // Add extra arguments
        for arg in extra_args {
            cmd.args(shellwords::split(arg).context("Failed to parse extra arguments")?);
        }

        debug!("Executing check command: {:?}", cmd);

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic check command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined_output = format!("{}\n{}", stdout, stderr).trim().to_string();

        let success = output.status.success();

        let result = CheckResult {
            success,
            output: combined_output,
            error: if success {
                None
            } else {
                Some(stderr.to_string())
            },
        };

        if success {
            info!("Repository check completed successfully");
        } else {
            warn!("Repository check failed: {}", stderr);
        }

        Ok(result)
    }

    /// List snapshots
    pub async fn list_snapshots(&self, password: &str, tags: Option<&[String]>) -> Result<String> {
        let mut cmd = self.base_command_with_password(password);
        cmd.arg("snapshots");
        cmd.arg("--compact");

        if let Some(tags) = tags {
            for tag in tags {
                cmd.arg("--tag").arg(tag);
            }
        }

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic snapshots command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to list snapshots: {}", error);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get repository stats
    pub async fn stats(&self, password: &str, snapshot: Option<&str>) -> Result<String> {
        let mut cmd = self.base_command_with_password(password);
        cmd.arg("stats");

        if let Some(snapshot) = snapshot {
            cmd.arg(snapshot);
        } else {
            cmd.arg("latest");
        }

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic stats command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to get repository stats: {}", error);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Get diff between two snapshots
    pub async fn diff(&self, password: &str, snapshot1: &str, snapshot2: &str) -> Result<String> {
        let mut cmd = self.base_command_with_password(password);
        cmd.arg("diff");
        cmd.arg(snapshot1);
        cmd.arg(snapshot2);

        let output = cmd
            .output()
            .await
            .context("Failed to execute restic diff command")?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to get snapshot diff: {}", error);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Create base command with common arguments and password
    fn base_command_with_password(&self, password: &str) -> AsyncCommand {
        let mut cmd = AsyncCommand::new("restic");

        // Set repository
        cmd.arg("--repo").arg(&self.repository);

        // Set password via environment variable (more secure than file)
        cmd.env("RESTIC_PASSWORD", password);

        // Set environment variables
        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        // Ensure clean environment for consistent behavior
        cmd.env(
            "HOME",
            std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()),
        );

        cmd
    }

    /// Extract snapshot ID from restic output
    fn extract_snapshot_id(&self, output: &str) -> Option<String> {
        let snapshot_regex = Regex::new(r"snapshot ([a-f0-9]{8}) saved").ok()?;
        snapshot_regex
            .captures(output)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Get backup statistics
    async fn get_backup_stats(
        &self,
        password: &str,
        tags: &[String],
        snapshot_id: &str,
        duration: u64,
    ) -> Result<BackupStats> {
        debug!("Getting backup statistics for snapshot: {}", snapshot_id);

        // Get latest snapshots for diff
        let snapshots_output = self.list_snapshots(password, Some(tags)).await?;
        let snapshot_ids = self.extract_latest_snapshot_ids(&snapshots_output, 2);

        let (added_size, removed_size) = if snapshot_ids.len() >= 2 {
            let diff_output = self
                .diff(password, &snapshot_ids[0], &snapshot_ids[1])
                .await?;
            self.parse_diff_output(&diff_output)
        } else {
            ("0 B".to_string(), "0 B".to_string())
        };

        // Get total size
        let stats_output = self.stats(password, Some("latest")).await?;
        let total_size = self
            .extract_total_size(&stats_output)
            .unwrap_or_else(|| "Unknown".to_string());

        Ok(BackupStats {
            timestamp: Utc::now(),
            snapshot_id: snapshot_id.to_string(),
            added_size,
            removed_size,
            total_size,
            duration_seconds: duration,
        })
    }

    /// Extract latest snapshot IDs from snapshots output
    fn extract_latest_snapshot_ids(&self, output: &str, count: usize) -> Vec<String> {
        let snapshot_regex = Regex::new(r"^([a-f0-9]{8})\s").unwrap();
        output
            .lines()
            .filter_map(|line| {
                snapshot_regex
                    .captures(line)
                    .and_then(|caps| caps.get(1))
                    .map(|m| m.as_str().to_string())
            })
            .take(count)
            .collect()
    }

    /// Parse diff output to extract added/removed sizes
    fn parse_diff_output(&self, output: &str) -> (String, String) {
        let added_regex = Regex::new(r"Added:\s+(.+)").unwrap();
        let removed_regex = Regex::new(r"Removed:\s+(.+)").unwrap();

        let added = added_regex
            .captures(output)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "0 B".to_string());

        let removed = removed_regex
            .captures(output)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "0 B".to_string());

        (added, removed)
    }

    /// Extract total size from stats output
    fn extract_total_size(&self, output: &str) -> Option<String> {
        let size_regex = Regex::new(r"Total Size:\s+(.+)").unwrap();
        size_regex
            .captures(output)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_restic_command() -> ResticCommand {
        ResticCommand {
            repository: "test-repo".to_string(),
            env_vars: HashMap::new(),
            verbosity: 1,
        }
    }

    #[test]
    fn test_extract_snapshot_id() {
        let restic = create_test_restic_command();
        let output = "Files:           1 new,     0 changed,     0 unmodified\nDirs:            1 new,     0 changed,     0 unmodified\nAdded to the repo: 123.456 KiB\n\nsnapshot a1b2c3d4 saved";

        let snapshot_id = restic.extract_snapshot_id(output);
        assert_eq!(snapshot_id, Some("a1b2c3d4".to_string()));
    }

    #[test]
    fn test_extract_latest_snapshot_ids() {
        let restic = create_test_restic_command();
        let output = "a1b2c3d4 2023-01-01 12:00:00 host /path tag1\nb2c3d4e5 2023-01-02 12:00:00 host /path tag1";

        let ids = restic.extract_latest_snapshot_ids(output, 2);
        assert_eq!(ids, vec!["a1b2c3d4".to_string(), "b2c3d4e5".to_string()]);
    }

    #[test]
    fn test_parse_diff_output() {
        let restic = create_test_restic_command();
        let output = "Files:         123 new,    45 changed,    67 unmodified\nDirs:           12 new,     5 changed,    89 unmodified\nAdded:   456.789 MiB\nRemoved: 123.456 KiB";

        let (added, removed) = restic.parse_diff_output(output);
        assert_eq!(added, "456.789 MiB");
        assert_eq!(removed, "123.456 KiB");
    }

    #[test]
    fn test_extract_total_size() {
        let restic = create_test_restic_command();
        let output = "Total File Count:   123\nTotal Size:         1.234 GiB";

        let size = restic.extract_total_size(output);
        assert_eq!(size, Some("1.234 GiB".to_string()));
    }
}
