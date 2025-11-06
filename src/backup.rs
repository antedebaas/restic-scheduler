use anyhow::{Context, Result};

use std::process::Stdio;
use tokio::process::Command;
use tokio::signal;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::config::{Config, ProfileConfig};
use crate::notification::{create_backup_notification, NotificationSender};
use crate::restic::{BackupResult, ResticCommand};
use crate::stats::StatsLogger;

pub struct BackupOperation {
    profile_name: String,
    profile: ProfileConfig,
    restic: ResticCommand,
    stats_logger: Option<StatsLogger>,
    notification_sender: Option<NotificationSender>,
}

impl BackupOperation {
    pub fn new(config: Config, profile_name: String) -> Result<Self> {
        let profile = config
            .get_profile(&profile_name)
            .ok_or_else(|| anyhow::anyhow!("Profile '{profile_name}' not found"))?
            .clone();

        let restic = ResticCommand::new(&profile).with_verbosity(config.global.verbosity_level);

        // Always create a stats logger since we always log to stdout
        // Also pass stats_dir for additional JSON file output
        let stats_logger = Some(
            StatsLogger::new(config.global.stats_dir.clone(), profile_name.clone())
                .with_rotation_config(config.global.log_rotation.clone()),
        );

        let notification_sender =
            if profile.notifications.email.is_some() || profile.notifications.webhook.is_some() {
                Some(NotificationSender::new(
                    profile.notifications.clone(),
                    profile_name.clone(),
                ))
            } else {
                None
            };

        Ok(Self {
            profile_name,
            profile,
            restic,
            stats_logger,
            notification_sender,
        })
    }

    /// Run the complete backup operation
    pub async fn run(&self) -> Result<BackupResult> {
        info!(
            "Starting backup operation for profile: {}",
            self.profile_name
        );
        let start_time = std::time::Instant::now();

        // Get repository password
        let password = match self.profile.get_password().await {
            Ok(pwd) => pwd,
            Err(e) => {
                let error_msg = format!("Failed to get repository password: {e}");
                error!("{}", error_msg);
                self.send_failure_notification(&error_msg, None).await;
                anyhow::bail!(error_msg);
            }
        };

        // Set up signal handling for graceful shutdown
        let _shutdown_guard = self.setup_signal_handling(&password).await?;

        // Check and initialize repository if needed
        if let Err(e) = self.ensure_repository_initialized(&password).await {
            let error_msg = format!("Failed to initialize repository: {e}");
            error!("{}", error_msg);
            self.send_failure_notification(&error_msg, None).await;
            anyhow::bail!(error_msg);
        }

        // Run pre-backup command if configured for this profile
        if let Some(ref command) = self.profile.pre_backup_command {
            if let Err(e) = self.run_pre_backup_command(command).await {
                let error_msg = format!("Pre-backup command failed: {e}");
                error!("{}", error_msg);
                self.send_failure_notification(&error_msg, None).await;
                anyhow::bail!(error_msg);
            }
        }

        // Unlock repository to clear any stale locks
        if let Err(e) = self.restic.unlock(&password).await {
            warn!("Failed to unlock repository: {}", e);
            // Note: We continue even if unlock fails as it might not be critical
        }

        // Perform the backup
        let backup_result = match self.perform_backup(&password).await {
            Ok(result) => result,
            Err(e) => {
                let error_msg = format!("Backup operation failed: {e}");
                error!("{}", error_msg);
                let duration = start_time.elapsed().as_secs();
                self.send_failure_notification(&error_msg, Some(duration))
                    .await;
                anyhow::bail!(error_msg);
            }
        };

        let duration = start_time.elapsed().as_secs();

        if !backup_result.success {
            let error_msg = match &backup_result.error {
                Some(restic_error) => format!("Backup failed: {restic_error}"),
                None => "Backup failed with unknown error".to_string(),
            };
            error!("{}", error_msg);
            self.send_failure_notification(&error_msg, Some(duration))
                .await;
            return Ok(backup_result);
        }

        // Clean up old snapshots according to retention policy
        if let Err(e) = self.cleanup_old_snapshots(&password).await {
            warn!("Failed to clean up old snapshots: {}", e);
            // Note: We continue even if cleanup fails as the backup itself was successful
        }

        // Log statistics if enabled
        if let (Some(ref logger), Some(ref stats)) = (&self.stats_logger, &backup_result.stats) {
            if let Err(e) = logger.log_stats(stats).await {
                warn!("Failed to log backup statistics: {}", e);
            }
        }

        // Send success notification
        self.send_success_notification(&backup_result, Some(duration))
            .await;

        info!("Backup operation completed successfully");
        Ok(backup_result)
    }

    /// Ensure repository is initialized
    async fn ensure_repository_initialized(&self, password: &str) -> Result<()> {
        // Try to list snapshots to check if repository exists
        match self.restic.list_snapshots(password, None).await {
            Ok(_) => {
                debug!("Repository is already initialized");
                Ok(())
            }
            Err(e) => {
                info!("Repository not found or not initialized, initializing now...");
                if let Err(init_error) = self.restic.init_repository(password).await {
                    anyhow::bail!(
                        "Failed to initialize repository. Original error: {e}. Init error: {init_error}"
                    );
                }
                Ok(())
            }
        }
    }

    /// Perform the actual backup
    async fn perform_backup(&self, password: &str) -> Result<BackupResult> {
        let exclude_patterns = self.profile.all_exclude_patterns();

        let one_file_system = !cfg!(windows); // --one-file-system not supported on Windows

        let result = self
            .restic
            .backup(
                password,
                &self.profile.backup_paths,
                &self.profile.backup_tags,
                &exclude_patterns,
                &self.profile.backup_extra_args,
                one_file_system,
            )
            .await
            .context("Backup operation failed")?;

        Ok(result)
    }

    /// Clean up old snapshots according to retention policy
    async fn cleanup_old_snapshots(&self, password: &str) -> Result<()> {
        let retention = &self.profile.retention;

        self.restic
            .forget(password, &self.profile.backup_tags, retention)
            .await
            .context("Failed to clean up old snapshots")?;

        Ok(())
    }

    /// Run pre-backup command
    async fn run_pre_backup_command(&self, command: &str) -> Result<()> {
        info!("Running pre-backup command: {}", command);

        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set environment variables from profile
        for (key, value) in self.profile.get_env_vars() {
            cmd.env(key, value);
        }

        let output = cmd
            .output()
            .await
            .with_context(|| format!("Failed to execute pre-backup command: {command}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "Pre-backup command failed with exit code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            info!("Pre-backup command output: {}", stdout.trim());
        }

        info!("Pre-backup command completed successfully");
        Ok(())
    }

    /// Send success notification
    async fn send_success_notification(&self, result: &BackupResult, duration: Option<u64>) {
        if let Some(ref sender) = self.notification_sender {
            let message = if let Some(ref stats) = result.stats {
                format!(
                    "Backup completed successfully. Added: {}, Removed: {}, Total size: {}",
                    stats.added_size, stats.removed_size, stats.total_size
                )
            } else {
                "Backup completed successfully".to_string()
            };

            let details = result.stats.as_ref().map(|stats| {
                format!(
                    "Snapshot ID: {}\nAdded: {}\nRemoved: {}\nTotal Size: {}\nDuration: {}s",
                    stats.snapshot_id,
                    stats.added_size,
                    stats.removed_size,
                    stats.total_size,
                    stats.duration_seconds
                )
            });

            let notification = create_backup_notification(true, message, details, duration);

            if let Err(e) = sender.send_notification(notification).await {
                warn!("Failed to send success notification: {}", e);
            }
        }
    }

    /// Send failure notification
    async fn send_failure_notification(&self, error_message: &str, duration: Option<u64>) {
        if let Some(ref sender) = self.notification_sender {
            let notification = create_backup_notification(
                false,
                error_message.to_string(),
                Some(error_message.to_string()),
                duration,
            );

            if let Err(e) = sender.send_notification(notification).await {
                warn!("Failed to send failure notification: {}", e);
            }
        }
    }

    /// Set up signal handling for graceful shutdown
    async fn setup_signal_handling(&self, password: &str) -> Result<SignalHandler> {
        SignalHandler::new(self.restic.clone(), password.to_string()).await
    }
}

/// Handle signals for graceful shutdown
pub struct SignalHandler {}

impl SignalHandler {
    async fn new(restic: ResticCommand, password: String) -> Result<Self> {
        let restic_clone = restic.clone();
        let password_clone = password.clone();
        let handler = Self {};

        // Spawn a task to handle signals
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                    .expect("Failed to install SIGTERM handler");
                let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                    .expect("Failed to install SIGINT handler");

                tokio::select! {
                    _ = sigterm.recv() => {
                        warn!("Received SIGTERM, initiating graceful shutdown");
                        Self::handle_shutdown(&restic_clone, &password_clone).await;
                    }
                    _ = sigint.recv() => {
                        warn!("Received SIGINT, initiating graceful shutdown");
                        Self::handle_shutdown(&restic_clone, &password_clone).await;
                    }
                }
            }

            #[cfg(windows)]
            {
                match signal::ctrl_c().await {
                    Ok(()) => {
                        warn!("Received Ctrl+C, initiating graceful shutdown");
                        Self::handle_shutdown(&restic_clone, &password_clone).await;
                    }
                    Err(err) => {
                        error!("Unable to listen for shutdown signal: {}", err);
                    }
                }
            }
        });

        Ok(handler)
    }

    async fn handle_shutdown(restic: &ResticCommand, password: &str) {
        info!("Cleaning up and unlocking repository before shutdown");

        // Give processes a chance to clean up
        sleep(Duration::from_millis(100)).await;

        // Unlock repository
        if let Err(e) = restic.unlock(password).await {
            error!("Failed to unlock repository during shutdown: {}", e);
        }

        // Exit gracefully
        std::process::exit(1);
    }
}

impl Drop for SignalHandler {
    fn drop(&mut self) {
        debug!("Signal handler dropped");
    }
}

/// Check if a backup is already running
pub async fn is_backup_running() -> bool {
    match Command::new("pgrep")
        .args(["-f", "restic backup"])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = stdout.trim().lines().collect();

            // Check if any processes are actual restic backups (not the scheduler)
            for line in lines {
                let pid: u32 = line.trim().parse().unwrap_or(0);
                if pid != std::process::id() {
                    return true;
                }
            }
            false
        }
        Err(_) => {
            // If pgrep is not available, assume no backup is running
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tempfile::TempDir;

    async fn create_test_backup_operation() -> (BackupOperation, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let _config_path = temp_dir.path().join("config.toml");

        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "default".to_string(),
            crate::config::ProfileConfig {
                repository: "b2:test-bucket".to_string(),
                repository_path: None,
                encryption_password: Some("test-password".to_string()),
                encryption_password_command: None,
                backup_paths: vec![temp_dir.path().to_path_buf()],
                backup_tags: vec!["test".to_string()],
                exclude_patterns: vec![],
                backup_extra_args: vec![],
                pre_backup_command: None,
                retention: crate::config::RetentionPolicy {
                    hours: 1,
                    days: 7,
                    weeks: 4,
                    months: 12,
                    years: 2,
                },
                backend: crate::config::BackendConfig {
                    b2: Some(crate::config::B2Config {
                        account_id: "test-id".to_string(),
                        account_key: "test-key".to_string(),
                        connections: 10,
                    }),
                    s3: None,
                },
                check: crate::config::CheckConfig::default(),
                notifications: crate::config::NotificationConfig::default(),
            },
        );

        let config = Config {
            global: crate::config::GlobalConfig {
                verbosity_level: 1,
                stats_dir: None,
                log_rotation: crate::config::LogRotationConfig::default(),
            },
            profiles,
        };

        let backup_op = BackupOperation::new(config, "default".to_string()).unwrap();
        (backup_op, temp_dir)
    }

    #[tokio::test]
    async fn test_backup_operation_creation() {
        let (backup_op, _temp_dir) = create_test_backup_operation().await;
        assert_eq!(backup_op.profile_name, "default");
        assert!(!backup_op.profile.backup_paths.is_empty());
    }

    #[tokio::test]
    async fn test_is_backup_running() {
        // This test may be flaky depending on system state
        let _running = is_backup_running().await;
        // Just ensure the function doesn't panic - no assertion needed
    }
}
