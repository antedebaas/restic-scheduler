use anyhow::Result;

use tracing::{debug, error, info, warn};

use crate::config::{Config, ProfileConfig};
use crate::notification::{create_check_notification, NotificationSender};
use crate::restic::{CheckResult, ResticCommand};

pub struct CheckOperation {
    profile_name: String,
    profile: ProfileConfig,
    restic: ResticCommand,
    notification_sender: Option<NotificationSender>,
}

impl CheckOperation {
    pub fn new(config: Config, profile_name: String) -> Result<Self> {
        let profile = config
            .get_profile(&profile_name)
            .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?
            .clone();

        let restic = ResticCommand::new(&profile).with_verbosity(config.global.verbosity_level);

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
            notification_sender,
        })
    }

    /// Run the repository check operation
    pub async fn run(&self) -> Result<CheckResult> {
        info!(
            "Starting repository check for profile: {}",
            self.profile_name
        );
        let start_time = std::time::Instant::now();

        if !self.profile.check.enabled {
            info!(
                "Repository check is disabled for profile: {}",
                self.profile_name
            );
            return Ok(CheckResult {
                success: true,
                output: "Check disabled".to_string(),
                error: None,
            });
        }

        // Get repository password
        let password = match self.profile.get_password().await {
            Ok(pwd) => pwd,
            Err(e) => {
                let error_msg = format!("Failed to get repository password: {}", e);
                let duration = start_time.elapsed().as_secs();
                self.send_failure_notification(&error_msg, Some(duration))
                    .await;
                anyhow::bail!(error_msg);
            }
        };

        // Note: We don't unlock the repository here like in backup operations
        // because check operations should not interfere with backup operations
        // and backup operations take precedence

        let result = match self
            .restic
            .check(&password, &self.profile.check.extra_args)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                let error_msg = format!("Repository check command failed: {}", e);
                error!("{}", error_msg);
                let duration = start_time.elapsed().as_secs();
                self.send_failure_notification(&error_msg, Some(duration))
                    .await;
                anyhow::bail!(error_msg);
            }
        };

        let duration = start_time.elapsed().as_secs();

        if result.success {
            info!(
                "Repository check completed successfully for profile: {}",
                self.profile_name
            );
            self.send_success_notification(&result, Some(duration))
                .await;
        } else {
            let error_msg = match &result.error {
                Some(restic_error) => {
                    format!(
                        "Repository check failed for profile '{}': {}",
                        self.profile_name, restic_error
                    )
                }
                None => {
                    format!(
                        "Repository check failed for profile '{}' with unknown error",
                        self.profile_name
                    )
                }
            };
            error!("{}", error_msg);
            self.send_failure_notification(&error_msg, Some(duration))
                .await;
        }

        Ok(result)
    }

    /// Check if repository is accessible
    pub async fn test_connection(&self) -> Result<(bool, Option<String>)> {
        debug!(
            "Testing repository connection for profile: {}",
            self.profile_name
        );

        let password = self.profile.get_password().await?;

        match self.restic.list_snapshots(&password, None).await {
            Ok(_) => {
                debug!("Repository connection test successful");
                Ok((true, None))
            }
            Err(e) => {
                let error_msg = format!(
                    "Repository connection test failed for profile '{}': {}",
                    self.profile_name, e
                );
                error!("{}", error_msg);
                Ok((false, Some(error_msg)))
            }
        }
    }

    /// Send success notification
    async fn send_success_notification(&self, result: &CheckResult, duration: Option<u64>) {
        if let Some(ref sender) = self.notification_sender {
            let message = "Repository check completed successfully".to_string();

            let notification =
                create_check_notification(true, message, Some(result.output.clone()), duration);

            if let Err(e) = sender.send_notification(notification).await {
                warn!("Failed to send success notification: {}", e);
            }
        }
    }

    /// Send failure notification
    async fn send_failure_notification(&self, error_message: &str, duration: Option<u64>) {
        if let Some(ref sender) = self.notification_sender {
            let notification =
                create_check_notification(false, error_message.to_string(), None, duration);

            if let Err(e) = sender.send_notification(notification).await {
                warn!("Failed to send failure notification: {}", e);
            }
        }
    }
}

/// Check multiple profiles
pub async fn check_all_profiles(config: &Config) -> Result<Vec<(String, CheckResult)>> {
    let mut results = Vec::new();

    for profile_name in config.profile_names() {
        info!("Checking profile: {}", profile_name);

        let check_op = CheckOperation::new(config.clone(), profile_name.clone())?;

        let result = check_op.run().await;

        match result {
            Ok(check_result) => {
                results.push((profile_name.clone(), check_result));
            }
            Err(e) => {
                warn!("Failed to check profile {}: {}", profile_name, e);
                results.push((
                    profile_name.clone(),
                    CheckResult {
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                    },
                ));
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn test_check_operation_creation() {
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "default".to_string(),
            crate::config::ProfileConfig {
                repository: "b2:test-bucket".to_string(),
                encryption_password: Some("test-password".to_string()),
                encryption_password_command: None,
                backup_paths: vec![std::path::PathBuf::from("/tmp")],
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
                stats_format: crate::config::StatsFormat::Json,
            },
            profiles,
        };

        let check_op = CheckOperation::new(config, "default".to_string()).unwrap();
        assert_eq!(check_op.profile_name, "default");
    }
}
