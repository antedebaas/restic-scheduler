use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::backup::{is_backup_running, BackupOperation};
use crate::check::{check_all_profiles, CheckOperation};
use crate::config::Config;
use crate::restic::ResticCommand;
use crate::stats::StatsLogger;

#[derive(Debug, Parser)]
#[command(name = "restic-scheduler")]
#[command(about = "Automatic restic backup scheduler")]
#[command(version)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/restic-scheduler/config.toml")]
    pub config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Backup profile to use (defaults to 'default' or first available)
    #[arg(short, long)]
    pub profile: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Perform a backup
    Backup,

    /// Check repository integrity (full verification)
    Check {
        /// Check all profiles instead of just the selected one
        #[arg(long)]
        all_profiles: bool,
    },

    /// List snapshots
    Snapshots {
        /// Filter by tag
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Show repository statistics
    Stats {
        /// Show stats for specific snapshot ID
        #[arg(short, long)]
        snapshot: Option<String>,
    },

    /// Show backup statistics
    BackupStats {
        /// Show stats for specific year (YYYY)
        #[arg(short, long)]
        year: Option<u32>,

        /// Show summary for last N days
        #[arg(short, long)]
        days: Option<u32>,

        /// Clean up statistics older than N years
        #[arg(long)]
        cleanup_older_than: Option<u32>,
    },

    /// Validate configuration file
    ValidateConfig,

    /// List available profiles
    ListProfiles,

    /// Test repository connection
    TestConnection,

    /// Show repository information
    Info,

    /// Unlock repository (remove stale locks)
    Unlock {
        /// Unlock all profiles instead of just the selected one
        #[arg(long)]
        all_profiles: bool,
    },
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        // Set up logging based on verbosity
        self.setup_logging();

        // Load configuration
        let config = self.load_config().await?;

        // Determine which profile to use
        let profile_name = self.determine_profile(&config)?;

        match self.command {
            Commands::Backup => self.run_backup(config, profile_name).await,
            Commands::Check { all_profiles } => {
                self.run_check(config, profile_name, all_profiles).await
            }

            Commands::Snapshots { ref tag } => {
                self.run_snapshots(config, profile_name, tag.clone()).await
            }
            Commands::Stats { ref snapshot } => {
                self.run_stats(config, profile_name, snapshot.clone()).await
            }
            Commands::BackupStats {
                year,
                days,
                cleanup_older_than,
            } => {
                self.run_backup_stats(config, year, days, cleanup_older_than)
                    .await
            }

            Commands::ValidateConfig => self.run_validate_config(config).await,
            Commands::ListProfiles => self.run_list_profiles(config).await,
            Commands::TestConnection => self.run_test_connection(config, profile_name).await,
            Commands::Info => self.run_info().await,
            Commands::Unlock { all_profiles } => {
                self.run_unlock(config, profile_name, all_profiles).await
            }
        }
    }

    fn setup_logging(&self) {
        use tracing_subscriber::{fmt, EnvFilter};

        let level = match self.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        };

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(format!("restic_scheduler={level}")));

        fmt().with_env_filter(filter).with_target(false).init();
    }

    async fn load_config(&self) -> Result<Config> {
        if !self.config.exists() {
            anyhow::bail!(
                "Configuration file not found: {}\n\nUse 'restic-scheduler generate-config' to create a sample configuration.",
                self.config.display()
            );
        }

        Config::from_file(&self.config)
    }

    fn determine_profile(&self, config: &Config) -> Result<String> {
        if let Some(ref profile) = self.profile {
            if config.get_profile(profile).is_none() {
                anyhow::bail!("Profile '{profile}' not found in configuration");
            }
            Ok(profile.clone())
        } else if let Some((name, _)) = config.get_default_profile() {
            Ok(name.clone())
        } else {
            anyhow::bail!("No profiles found in configuration");
        }
    }

    async fn run_backup(&self, config: Config, profile_name: String) -> Result<()> {
        // Check if another backup is running
        if is_backup_running().await {
            println!("Another restic process is running, skipping backup");
            return Ok(());
        }

        // Verify restic is available
        match ResticCommand::check_restic_available().await {
            Ok(version) => println!("Using restic version: {version}"),
            Err(e) => anyhow::bail!("Restic not available: {e}"),
        }

        let backup_op = BackupOperation::new(config, profile_name)?;
        let result = backup_op.run().await?;

        if result.success {
            println!("Backup completed successfully");
            if let Some(stats) = result.stats {
                println!("  Snapshot ID: {}", stats.snapshot_id);
                println!("  Added: {}", stats.added_size);
                println!("  Removed: {}", stats.removed_size);
                println!("  Total size: {}", stats.total_size);
                println!("  Duration: {}s", stats.duration_seconds);
            }
        } else {
            anyhow::bail!(
                "Backup failed: {}",
                result.error.unwrap_or_else(|| "Unknown error".to_string())
            );
        }

        Ok(())
    }

    async fn run_check(
        &self,
        config: Config,
        profile_name: String,
        all_profiles: bool,
    ) -> Result<()> {
        if all_profiles {
            let results = check_all_profiles(&config).await?;

            println!("Repository check results:");
            for (profile, result) in results {
                println!(
                    "  Profile '{}': {}",
                    profile,
                    if result.success { "OK" } else { "FAILED" }
                );
                if !result.success {
                    if let Some(error) = result.error {
                        println!("    Error: {error}");
                    }
                }
            }
        } else {
            let check_op = CheckOperation::new(config, profile_name.clone())?;
            let result = check_op.run().await?;

            if result.success {
                println!("Repository check passed for profile '{profile_name}'");
            } else {
                println!("Repository check failed for profile '{profile_name}'");
                if let Some(error) = result.error {
                    println!("Error: {error}");
                }
                std::process::exit(1);
            }
        }

        Ok(())
    }

    async fn run_snapshots(
        &self,
        config: Config,
        profile_name: String,
        tag: Option<String>,
    ) -> Result<()> {
        let profile = config
            .get_profile(&profile_name)
            .ok_or_else(|| anyhow::anyhow!("Profile '{profile_name}' not found"))?;

        let restic = ResticCommand::new(profile).with_verbosity(config.global.verbosity_level);
        let password = profile.get_password().await?;

        let tags = tag.map(|t| vec![t]);
        let snapshots = restic.list_snapshots(&password, tags.as_deref()).await?;

        println!("Snapshots for profile '{profile_name}':");
        println!("{snapshots}");

        Ok(())
    }

    async fn run_stats(
        &self,
        config: Config,
        profile_name: String,
        snapshot: Option<String>,
    ) -> Result<()> {
        let profile = config
            .get_profile(&profile_name)
            .ok_or_else(|| anyhow::anyhow!("Profile '{profile_name}' not found"))?;

        let restic = ResticCommand::new(profile).with_verbosity(config.global.verbosity_level);
        let password = profile.get_password().await?;
        let stats = restic.stats(&password, snapshot.as_deref()).await?;

        println!("Repository statistics for profile '{profile_name}':");
        println!("{stats}");

        Ok(())
    }

    async fn run_backup_stats(
        &self,
        config: Config,
        year: Option<u32>,
        days: Option<u32>,
        cleanup_older_than: Option<u32>,
    ) -> Result<()> {
        // For reading existing stats, we need a stats directory
        if config.global.stats_dir.is_none() {
            return Err(anyhow::anyhow!(
                "Statistics directory must be configured for reading stats"
            ));
        }

        // Use a default profile name for stats operations since we're reading all profiles
        let logger = StatsLogger::new(config.global.stats_dir.clone(), "stats".to_string())
            .with_rotation_config(config.global.log_rotation.clone());

        if let Some(years_to_keep) = cleanup_older_than {
            let removed = logger.cleanup_old_stats(years_to_keep).await?;
            println!("Cleaned up {removed} old statistics files");
            return Ok(());
        }

        if year.is_some() || days.is_some() {
            let summary = logger.get_summary(days).await?;
            println!("{summary}");
        } else {
            let stats = logger.read_stats(year).await?;

            if stats.is_empty() {
                println!("No backup statistics found");
                return Ok(());
            }

            println!("Backup Statistics:");
            println!(
                "{:<20} {:<12} {:<12} {:<12} {:<12} {:<10}",
                "Date", "Snapshot", "Added", "Removed", "Total", "Duration"
            );
            println!("{}", "-".repeat(80));

            for stat in stats.iter().take(20) {
                // Show last 20 entries
                println!(
                    "{:<20} {:<12} {:<12} {:<12} {:<12} {:<10}s",
                    stat.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    &stat.snapshot_id[..8.min(stat.snapshot_id.len())], // Truncate snapshot ID
                    stat.added_size,
                    stat.removed_size,
                    stat.total_size,
                    stat.duration_seconds
                );
            }

            if stats.len() > 20 {
                println!("... and {} more entries", stats.len() - 20);
            }
        }

        Ok(())
    }

    async fn run_validate_config(&self, config: Config) -> Result<()> {
        println!("Validating configuration file: {}", self.config.display());

        config.validate()?;

        println!("Configuration is valid");
        println!("Found {} profile(s):", config.profiles.len());

        for (name, profile) in &config.profiles {
            println!(
                "  - {}: {} -> {}",
                name,
                profile
                    .backup_paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                profile.repository
            );
        }

        Ok(())
    }

    async fn run_list_profiles(&self, config: Config) -> Result<()> {
        let profiles = config.profile_names();

        if profiles.is_empty() {
            println!("No profiles found in configuration");
            return Ok(());
        }

        println!("Available profiles:");
        for profile_name in profiles {
            let profile = config.get_profile(profile_name).unwrap();
            println!(
                "  {}: {} paths -> {}",
                profile_name,
                profile.backup_paths.len(),
                profile.repository
            );
        }

        Ok(())
    }

    async fn run_test_connection(&self, config: Config, profile_name: String) -> Result<()> {
        let check_op = CheckOperation::new(config, profile_name.clone())?;

        println!("Testing connection to repository for profile '{profile_name}'...");

        match check_op.test_connection().await? {
            (true, _) => {
                println!("Connection successful");
            }
            (false, Some(error_msg)) => {
                println!("Connection failed: {error_msg}");
                std::process::exit(1);
            }
            (false, None) => {
                println!("Connection failed with unknown error");
                std::process::exit(1);
            }
        }

        Ok(())
    }

    async fn run_info(&self) -> Result<()> {
        println!("Restic Scheduler");
        println!("================");

        match ResticCommand::check_restic_available().await {
            Ok(version) => println!("Restic version: {version}"),
            Err(_) => println!("Restic: Not available"),
        }

        println!("Configuration file: {}", self.config.display());
        println!("Config exists: {}", self.config.exists());

        if let Some(profile) = &self.profile {
            println!("Selected profile: {profile}");
        }

        Ok(())
    }

    async fn run_unlock(
        &self,
        config: Config,
        profile_name: String,
        all_profiles: bool,
    ) -> Result<()> {
        if all_profiles {
            let profile_names = config.profile_names();

            if profile_names.is_empty() {
                println!("No profiles found in configuration");
                return Ok(());
            }

            println!("Unlocking repositories for all profiles...");
            let mut failed_profiles = Vec::new();

            for profile_name in profile_names {
                let profile = config.get_profile(profile_name).unwrap();
                let restic =
                    ResticCommand::new(profile).with_verbosity(config.global.verbosity_level);

                print!("  Unlocking profile '{profile_name}'... ");

                match profile.get_password().await {
                    Ok(password) => match restic.unlock(&password).await {
                        Ok(()) => {
                            println!("OK");
                        }
                        Err(e) => {
                            println!("FAILED: {e}");
                            failed_profiles.push(profile_name.to_string());
                        }
                    },
                    Err(e) => {
                        println!("FAILED: {e}");
                        failed_profiles.push(profile_name.to_string());
                    }
                }
            }

            if !failed_profiles.is_empty() {
                anyhow::bail!(
                    "Failed to unlock {} profile(s): {}",
                    failed_profiles.len(),
                    failed_profiles.join(", ")
                );
            }

            println!("All repositories unlocked successfully");
        } else {
            let profile = config
                .get_profile(&profile_name)
                .ok_or_else(|| anyhow::anyhow!("Profile '{profile_name}' not found"))?;

            let restic = ResticCommand::new(profile).with_verbosity(config.global.verbosity_level);
            let password = profile.get_password().await?;

            println!("Unlocking repository for profile '{profile_name}'...");

            match restic.unlock(&password).await {
                Ok(()) => {
                    println!("Repository unlocked successfully");
                }
                Err(e) => {
                    anyhow::bail!("Failed to unlock repository: {e}");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        use clap::Parser;

        let cli = Cli::try_parse_from(["restic-scheduler", "backup"]).unwrap();
        assert!(matches!(cli.command, Commands::Backup));
    }

    #[test]
    fn test_cli_with_profile() {
        use clap::Parser;

        let cli = Cli::try_parse_from(["restic-scheduler", "--profile", "test", "backup"]).unwrap();

        assert_eq!(cli.profile, Some("test".to_string()));
    }

    #[test]
    fn test_cli_with_config_file() {
        use clap::Parser;

        let cli = Cli::try_parse_from([
            "restic-scheduler",
            "--config",
            "/custom/config.toml",
            "backup",
        ])
        .unwrap();

        assert_eq!(cli.config, PathBuf::from("/custom/config.toml"));
    }

    #[test]
    fn test_cli_unlock_command() {
        use clap::Parser;

        let cli = Cli::try_parse_from(["restic-scheduler", "unlock"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Unlock {
                all_profiles: false
            }
        ));
    }

    #[test]
    fn test_cli_unlock_all_profiles() {
        use clap::Parser;

        let cli = Cli::try_parse_from(["restic-scheduler", "unlock", "--all-profiles"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Unlock { all_profiles: true }
        ));
    }
}
