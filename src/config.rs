use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogRotationConfig {
    /// Maximum size of individual log files before rotation (in MB)
    #[serde(default = "default_max_log_size")]
    pub max_log_size_mb: u64,

    /// Maximum age of log files in days before cleanup
    #[serde(default = "default_max_log_age_days")]
    pub max_log_age_days: u32,

    /// Whether to compress rotated log files
    #[serde(default = "default_compress_rotated")]
    pub compress_rotated: bool,

    /// Maximum number of rotated files to keep per log file
    #[serde(default = "default_max_rotated_files")]
    pub max_rotated_files: u32,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_log_size_mb: default_max_log_size(),
            max_log_age_days: default_max_log_age_days(),
            compress_rotated: default_compress_rotated(),
            max_rotated_files: default_max_rotated_files(),
        }
    }
}

fn default_max_log_size() -> u64 {
    100 // 100 MB
}

fn default_max_log_age_days() -> u32 {
    30 // 30 days
}

fn default_compress_rotated() -> bool {
    true
}

fn default_max_rotated_files() -> u32 {
    10
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GlobalConfig {
    /// Verbosity level from 0-3. 0 means no verbose output.
    #[serde(default = "default_verbosity")]
    pub verbosity_level: u8,

    /// Directory for backup statistics logs (JSON format)
    /// When specified, statistics will also be written to files in addition to stdout
    pub stats_dir: Option<PathBuf>,

    /// Log rotation configuration
    #[serde(default)]
    pub log_rotation: LogRotationConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProfileConfig {
    /// Restic repository URL (e.g., "b2:bucket-name", "/path/to/repo", "s3:bucket/path", etc.)
    pub repository: String,

    /// Direct encryption password value (not recommended for production)
    pub encryption_password: Option<String>,

    /// Command to execute to get the encryption password
    pub encryption_password_command: Option<String>,

    /// Paths to backup (multiple paths supported)
    pub backup_paths: Vec<PathBuf>,

    /// Tags to identify backup snapshots (multiple tags supported)
    #[serde(default = "default_backup_tags")]
    pub backup_tags: Vec<String>,

    /// Exclude patterns (files and directories to exclude from backup)
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// Extra arguments to pass to restic backup command
    #[serde(default)]
    pub backup_extra_args: Vec<String>,

    /// Pre-backup command to run before each backup
    pub pre_backup_command: Option<String>,

    /// Retention policy for old backups
    pub retention: RetentionPolicy,

    /// Backend-specific configuration
    #[serde(default)]
    pub backend: BackendConfig,

    /// Check repository integrity settings
    #[serde(default)]
    pub check: CheckConfig,

    /// Notification settings for this profile
    #[serde(default)]
    pub notifications: NotificationConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetentionPolicy {
    /// Number of hourly backups to keep
    #[serde(default = "default_retention_hours")]
    pub hours: u32,

    /// Number of daily backups to keep
    #[serde(default = "default_retention_days")]
    pub days: u32,

    /// Number of weekly backups to keep
    #[serde(default = "default_retention_weeks")]
    pub weeks: u32,

    /// Number of monthly backups to keep
    #[serde(default = "default_retention_months")]
    pub months: u32,

    /// Number of yearly backups to keep
    #[serde(default = "default_retention_years")]
    pub years: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BackendConfig {
    /// Backblaze B2 configuration
    pub b2: Option<B2Config>,

    /// Amazon S3 (and compatible) configuration
    pub s3: Option<S3Config>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct B2Config {
    /// B2 Account ID (Key ID)
    pub account_id: String,

    /// B2 Application Key
    pub account_key: String,

    /// Number of concurrent connections to B2
    #[serde(default = "default_b2_connections")]
    pub connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckConfig {
    /// Whether to enable repository checks
    #[serde(default = "default_check_enabled")]
    pub enabled: bool,

    /// Extra arguments for restic check command
    #[serde(default)]
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Config {
    /// S3 Access Key ID
    pub access_key_id: String,

    /// S3 Secret Access Key
    pub secret_access_key: String,

    /// S3 Region
    #[serde(default = "default_s3_region")]
    pub region: String,

    /// S3 Endpoint URL (for S3-compatible services)
    pub endpoint: Option<String>,

    /// Use path-style addressing
    #[serde(default)]
    pub path_style: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NotificationConfig {
    /// Email notification settings
    pub email: Option<EmailConfig>,

    /// Webhook notification settings
    pub webhook: Option<WebhookConfig>,

    /// Command notification settings
    pub command: Option<CommandConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailConfig {
    /// Whether to notify on successful backups
    #[serde(default)]
    pub notify_on_success: bool,

    /// Whether to notify on backup failures
    #[serde(default = "default_notify_on_failure")]
    pub notify_on_failure: bool,

    /// SMTP server hostname
    pub smtp_server: String,

    /// SMTP server port
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,

    /// SMTP username
    pub smtp_username: String,

    /// SMTP password
    pub smtp_password: String,

    /// Sender email address
    pub from: String,

    /// Recipient email addresses
    pub to: Vec<String>,

    /// Use TLS encryption
    #[serde(default = "default_smtp_tls")]
    pub use_tls: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    /// Whether to notify on successful backups
    #[serde(default)]
    pub notify_on_success: bool,

    /// Whether to notify on backup failures
    #[serde(default = "default_notify_on_failure")]
    pub notify_on_failure: bool,

    /// Webhook URL
    pub url: String,

    /// HTTP method (GET, POST, etc.)
    #[serde(default = "default_webhook_method")]
    pub method: String,

    /// Additional HTTP headers (Content-Type: application/json is set by default)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request timeout in seconds
    #[serde(default = "default_webhook_timeout")]
    pub timeout: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandConfig {
    /// Whether to notify on successful backups
    #[serde(default)]
    pub notify_on_success: bool,

    /// Whether to notify on backup failures
    #[serde(default = "default_notify_on_failure")]
    pub notify_on_failure: bool,

    /// Command to execute for notifications
    pub command: String,

    /// Arguments to pass to the command
    #[serde(default)]
    pub args: Vec<String>,

    /// Timeout for command execution in seconds
    #[serde(default = "default_command_timeout")]
    pub timeout: u32,
}

// Default values
fn default_verbosity() -> u8 {
    0
}
fn default_backup_tags() -> Vec<String> {
    vec!["restic-scheduler".to_string()]
}

fn default_retention_hours() -> u32 {
    1
}
fn default_retention_days() -> u32 {
    14
}
fn default_retention_weeks() -> u32 {
    16
}
fn default_retention_months() -> u32 {
    18
}
fn default_retention_years() -> u32 {
    3
}
fn default_b2_connections() -> u32 {
    10
}
fn default_check_enabled() -> bool {
    true
}
fn default_s3_region() -> String {
    "us-east-1".to_string()
}
fn default_notify_on_failure() -> bool {
    true
}
fn default_smtp_port() -> u16 {
    587
}
fn default_smtp_tls() -> bool {
    true
}
fn default_webhook_method() -> String {
    "POST".to_string()
}
fn default_webhook_timeout() -> u32 {
    30
}

fn default_command_timeout() -> u32 {
    30
}

impl Default for CheckConfig {
    fn default() -> Self {
        Self {
            enabled: default_check_enabled(),
            extra_args: Vec::new(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))?;

        config.validate()?;
        Ok(config)
    }

    /// Get a specific profile by name
    pub fn get_profile(&self, name: &str) -> Option<&ProfileConfig> {
        self.profiles.get(name)
    }

    /// Get the default profile (named "default") or the first available profile
    pub fn get_default_profile(&self) -> Option<(&String, &ProfileConfig)> {
        self.profiles
            .get_key_value("default")
            .or_else(|| self.profiles.iter().next())
    }

    /// List all available profile names
    pub fn profile_names(&self) -> Vec<&String> {
        self.profiles.keys().collect()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.profiles.is_empty() {
            anyhow::bail!("At least one backup profile must be configured");
        }

        for (name, profile) in &self.profiles {
            profile
                .validate()
                .with_context(|| format!("Invalid configuration for profile '{name}'"))?;
        }

        Ok(())
    }
}

impl ProfileConfig {
    /// Validate the profile configuration
    pub fn validate(&self) -> Result<()> {
        if self.repository.is_empty() {
            anyhow::bail!("Repository URL cannot be empty");
        }

        if self.backup_paths.is_empty() {
            anyhow::bail!("At least one backup path must be specified");
        }

        // Validate password configuration
        self.validate_password()?;

        // Validate backend configuration
        if self.repository.starts_with("s3:") && self.backend.s3.is_none() {
            anyhow::bail!("S3 configuration required for S3 repository");
        }

        if self.repository.starts_with("b2:") && self.backend.b2.is_none() {
            anyhow::bail!("B2 configuration required for B2 repository");
        }

        for path in &self.backup_paths {
            if !path.exists() {
                tracing::warn!("Backup path does not exist: {}", path.display());
            }
        }

        Ok(())
    }

    /// Validate password configuration
    fn validate_password(&self) -> Result<()> {
        match (&self.encryption_password, &self.encryption_password_command) {
            (None, None) => {
                anyhow::bail!("Either 'encryption_password' or 'encryption_password_command' must be specified");
            }
            (Some(_), Some(_)) => {
                anyhow::bail!("Cannot specify both 'encryption_password' and 'encryption_password_command' - choose one");
            }
            (Some(pwd), None) => {
                if pwd.is_empty() {
                    anyhow::bail!("Encryption password cannot be empty");
                }
            }
            (None, Some(cmd)) => {
                if cmd.is_empty() {
                    anyhow::bail!("Encryption password command cannot be empty");
                }
            }
        }
        Ok(())
    }

    /// Get all exclude patterns (profile-specific only)
    pub fn all_exclude_patterns(&self) -> Vec<String> {
        self.exclude_patterns.clone()
    }

    /// Get environment variables for this profile's backend
    pub fn get_env_vars(&self) -> HashMap<String, String> {
        let mut env = HashMap::new();

        if let Some(b2) = &self.backend.b2 {
            env.insert("B2_ACCOUNT_ID".to_string(), b2.account_id.clone());
            env.insert("B2_ACCOUNT_KEY".to_string(), b2.account_key.clone());
            env.insert("B2_CONNECTIONS".to_string(), b2.connections.to_string());
        }

        if let Some(s3) = &self.backend.s3 {
            env.insert("AWS_ACCESS_KEY_ID".to_string(), s3.access_key_id.clone());
            env.insert(
                "AWS_SECRET_ACCESS_KEY".to_string(),
                s3.secret_access_key.clone(),
            );
            env.insert("AWS_DEFAULT_REGION".to_string(), s3.region.clone());

            if let Some(endpoint) = &s3.endpoint {
                env.insert("AWS_S3_ENDPOINT".to_string(), endpoint.clone());
            }

            if s3.path_style {
                env.insert("AWS_S3_FORCE_PATH_STYLE".to_string(), "true".to_string());
            }
        }

        env
    }

    /// Get the repository password
    pub async fn get_password(&self) -> Result<String> {
        if let Some(password) = &self.encryption_password {
            Ok(password.clone())
        } else if let Some(command) = &self.encryption_password_command {
            self.get_password_from_command(command).await
        } else {
            anyhow::bail!("No password source configured")
        }
    }

    /// Get password from external command
    async fn get_password_from_command(&self, command: &str) -> Result<String> {
        use tokio::process::Command;

        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .await
            .with_context(|| format!("Failed to execute password command: {command}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Password command failed: {stderr}");
        }

        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if password.is_empty() {
            anyhow::bail!("Password command returned empty result");
        }

        Ok(password)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStats {
    pub timestamp: DateTime<Utc>,
    pub snapshot_id: String,
    pub added_size: String,
    pub removed_size: String,
    pub total_size: String,
    pub duration_seconds: u64,
}

impl BackupStats {
    /// Convert to JSON Lines format (single line JSON)
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        // Test valid password
        let mut profile = ProfileConfig {
            repository: "test-repo".to_string(),
            encryption_password: Some("test-password".to_string()),
            encryption_password_command: None,
            backup_paths: vec![std::path::PathBuf::from("/tmp")],
            backup_tags: vec!["test".to_string()],
            exclude_patterns: vec![],
            backup_extra_args: vec![],
            pre_backup_command: None,
            retention: RetentionPolicy {
                hours: 24,
                days: 7,
                weeks: 4,
                months: 12,
                years: 2,
            },
            backend: BackendConfig::default(),
            check: CheckConfig::default(),
            notifications: NotificationConfig::default(),
        };
        assert!(profile.validate_password().is_ok());

        // Test valid password command
        profile.encryption_password = None;
        profile.encryption_password_command = Some("echo test".to_string());
        assert!(profile.validate_password().is_ok());

        // Test both password and command (should fail)
        profile.encryption_password = Some("test".to_string());
        profile.encryption_password_command = Some("echo test".to_string());
        assert!(profile.validate_password().is_err());

        // Test no password or command (should fail)
        profile.encryption_password = None;
        profile.encryption_password_command = None;
        assert!(profile.validate_password().is_err());

        // Test empty password (should fail)
        profile.encryption_password = Some("".to_string());
        profile.encryption_password_command = None;
        assert!(profile.validate_password().is_err());

        // Test empty command (should fail)
        profile.encryption_password = None;
        profile.encryption_password_command = Some("".to_string());
        assert!(profile.validate_password().is_err());
    }

    #[tokio::test]
    async fn test_get_password() {
        // Test direct password
        let profile = ProfileConfig {
            repository: "test-repo".to_string(),
            encryption_password: Some("direct-password".to_string()),
            encryption_password_command: None,
            backup_paths: vec![std::path::PathBuf::from("/tmp")],
            backup_tags: vec!["test".to_string()],
            exclude_patterns: vec![],
            backup_extra_args: vec![],
            pre_backup_command: None,
            retention: RetentionPolicy {
                hours: 24,
                days: 7,
                weeks: 4,
                months: 12,
                years: 2,
            },
            backend: BackendConfig::default(),
            check: CheckConfig::default(),
            notifications: NotificationConfig::default(),
        };

        let password = profile.get_password().await.unwrap();
        assert_eq!(password, "direct-password");

        // Test password command (echo should work on most systems)
        let profile_cmd = ProfileConfig {
            repository: "test-repo".to_string(),
            encryption_password: None,
            encryption_password_command: Some("echo 'command-password'".to_string()),
            backup_paths: vec![std::path::PathBuf::from("/tmp")],
            backup_tags: vec!["test".to_string()],
            exclude_patterns: vec![],
            backup_extra_args: vec![],
            pre_backup_command: None,
            retention: RetentionPolicy {
                hours: 24,
                days: 7,
                weeks: 4,
                months: 12,
                years: 2,
            },
            backend: BackendConfig::default(),
            check: CheckConfig::default(),
            notifications: NotificationConfig::default(),
        };

        let password_cmd = profile_cmd.get_password().await.unwrap();
        assert_eq!(password_cmd, "command-password");
    }

    #[test]
    fn test_config_validation() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "test".to_string(),
            ProfileConfig {
                repository: "b2:test-bucket".to_string(),
                encryption_password: Some("test-password".to_string()),
                encryption_password_command: None,
                backup_paths: vec![PathBuf::from("/tmp")],
                backup_tags: vec!["test".to_string()],
                exclude_patterns: vec![],
                backup_extra_args: vec![],
                pre_backup_command: None,
                retention: RetentionPolicy {
                    hours: 1,
                    days: 7,
                    weeks: 4,
                    months: 12,
                    years: 2,
                },
                backend: BackendConfig {
                    b2: Some(B2Config {
                        account_id: "test-id".to_string(),
                        account_key: "test-key".to_string(),
                        connections: 10,
                    }),
                    s3: None,
                },
                check: CheckConfig::default(),
                notifications: NotificationConfig::default(),
            },
        );

        let mut config = Config {
            global: GlobalConfig {
                verbosity_level: 1,
                stats_dir: None,
                log_rotation: LogRotationConfig::default(),
            },
            profiles,
        };

        assert!(config.validate().is_ok());

        // Test empty profiles
        config.profiles.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_profile_validation() {
        let mut profile = ProfileConfig {
            repository: "b2:test-bucket".to_string(),
            encryption_password: Some("test-password".to_string()),
            encryption_password_command: None,
            backup_paths: vec![PathBuf::from("/tmp")],
            backup_tags: vec!["test".to_string()],
            exclude_patterns: vec![],
            backup_extra_args: vec![],
            pre_backup_command: None,
            retention: RetentionPolicy {
                hours: 1,
                days: 7,
                weeks: 4,
                months: 12,
                years: 2,
            },
            backend: BackendConfig {
                b2: Some(B2Config {
                    account_id: "test-id".to_string(),
                    account_key: "test-key".to_string(),
                    connections: 10,
                }),
                s3: None,
            },
            check: CheckConfig::default(),
            notifications: NotificationConfig::default(),
        };

        assert!(profile.validate().is_ok());

        // Test empty repository
        profile.repository = String::new();
        assert!(profile.validate().is_err());

        // Test empty backup paths
        profile.repository = "b2:test".to_string();
        profile.backup_paths.clear();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn test_backup_tags_format() {
        let config_toml = r#"
[global]
verbosity_level = 1

[profiles.test]
repository = "b2:test-bucket"
backup_paths = ["/tmp/test"]
backup_tags = ["tag1", "tag2", "tag3"]
encryption_password = "test-password"

[profiles.test.retention]
hours = 24
days = 7
weeks = 4
months = 12
years = 2

[profiles.test.backend.b2]
account_id = "test-id"
account_key = "test-key"
"#;

        let config: Config = toml::from_str(config_toml).unwrap();
        let profile = config.profiles.get("test").unwrap();

        assert_eq!(profile.backup_tags, vec!["tag1", "tag2", "tag3"]);
    }

    #[test]
    fn test_default_backup_tags() {
        let config_toml = r#"
[global]
verbosity_level = 1

[profiles.test]
repository = "b2:test-bucket"
backup_paths = ["/tmp/test"]
encryption_password = "test-password"

[profiles.test.retention]
hours = 24
days = 7
weeks = 4
months = 12
years = 2

[profiles.test.backend.b2]
account_id = "test-id"
account_key = "test-key"
"#;

        let config: Config = toml::from_str(config_toml).unwrap();
        let profile = config.profiles.get("test").unwrap();

        // Should use default backup tags when none specified
        assert_eq!(profile.backup_tags, vec!["restic-scheduler"]);
    }
}
