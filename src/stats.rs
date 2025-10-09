use anyhow::{Context, Result};
use chrono::{Datelike, Utc};
use std::path::PathBuf;
use tokio::fs::{create_dir_all, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::config::{BackupStats, StatsFormat};

pub struct StatsLogger {
    stats_dir: Option<PathBuf>,
    format: StatsFormat,
    profile_name: String,
}

impl StatsLogger {
    pub fn new(stats_dir: Option<PathBuf>, format: StatsFormat, profile_name: String) -> Self {
        Self {
            stats_dir,
            format,
            profile_name,
        }
    }

    /// Log backup statistics using the configured format
    /// Always logs to stdout and additionally to the configured output format
    pub async fn log_stats(&self, stats: &BackupStats) -> Result<()> {
        // Always log to stdout first
        self.log_structured_stdout(stats).await?;

        // Additionally log to configured format
        match self.format {
            StatsFormat::Json => self.log_json_lines(stats).await,
            StatsFormat::Logfile => self.log_structured_file(stats).await,
        }
    }

    /// Log statistics as structured log events to stdout
    async fn log_structured_stdout(&self, stats: &BackupStats) -> Result<()> {
        info!(
            profile = %self.profile_name,
            timestamp = %stats.timestamp,
            snapshot_id = %stats.snapshot_id,
            added_size = %stats.added_size,
            removed_size = %stats.removed_size,
            total_size = %stats.total_size,
            duration_seconds = stats.duration_seconds,
            "Backup completed"
        );
        Ok(())
    }

    /// Log statistics as structured log events to profile-named log file
    async fn log_structured_file(&self, stats: &BackupStats) -> Result<()> {
        let stats_dir = match self.stats_dir.as_ref() {
            Some(dir) => dir,
            None => {
                debug!("No stats directory configured, skipping logfile logging");
                return Ok(());
            }
        };

        // Ensure the stats directory exists
        create_dir_all(stats_dir).await.with_context(|| {
            format!("Failed to create stats directory: {}", stats_dir.display())
        })?;

        let log_file = stats_dir.join(format!("{}.log", self.profile_name));

        debug!("Logging structured backup stats to: {}", log_file.display());

        // Open file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .await
            .with_context(|| format!("Failed to open stats log file: {}", log_file.display()))?;

        // Write structured log entry
        let log_entry = format!(
            "{} INFO profile={} timestamp={} snapshot_id={} added_size=\"{}\" removed_size=\"{}\" total_size=\"{}\" duration_seconds={} msg=\"Backup completed\"\n",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ"),
            self.profile_name,
            stats.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            stats.snapshot_id,
            stats.added_size,
            stats.removed_size,
            stats.total_size,
            stats.duration_seconds
        );

        file.write_all(log_entry.as_bytes())
            .await
            .context("Failed to write structured log entry")?;

        file.flush()
            .await
            .context("Failed to flush stats log file")?;

        debug!("Structured backup stats logged successfully");
        Ok(())
    }

    /// Log statistics to JSON Lines files
    async fn log_json_lines(&self, stats: &BackupStats) -> Result<()> {
        let stats_dir = match self.stats_dir.as_ref() {
            Some(dir) => dir,
            None => {
                debug!("No stats directory configured, skipping JSON file logging");
                return Ok(());
            }
        };

        // Ensure the stats directory exists
        create_dir_all(stats_dir).await.with_context(|| {
            format!("Failed to create stats directory: {}", stats_dir.display())
        })?;

        let year = stats.timestamp.format("%Y").to_string();
        let log_file = stats_dir.join(format!("{}-stats.jsonl", year));

        debug!("Logging backup stats to: {}", log_file.display());

        // Open file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .await
            .with_context(|| format!("Failed to open stats log file: {}", log_file.display()))?;

        // Write the stats record as JSON Lines
        let json_line = stats
            .to_json_line()
            .context("Failed to serialize stats to JSON")?;

        file.write_all(format!("{}\n", json_line).as_bytes())
            .await
            .context("Failed to write stats record")?;

        file.flush()
            .await
            .context("Failed to flush stats log file")?;

        debug!("Backup stats logged successfully");
        Ok(())
    }

    /// Read backup statistics from JSON Lines files
    pub async fn read_stats(&self, year: Option<u32>) -> Result<Vec<BackupStats>> {
        match self.format {
            StatsFormat::Logfile => {
                // Cannot read back from structured log files easily
                warn!("Cannot read stats from Logfile format - structured logs are not easily parseable");
                Ok(Vec::new())
            }
            StatsFormat::Json => {
                if self.stats_dir.is_none() {
                    warn!("No stats directory configured, cannot read stats");
                    return Ok(Vec::new());
                }
                self.read_json_lines_stats(year).await
            }
        }
    }

    /// Read statistics from JSON Lines files
    async fn read_json_lines_stats(&self, year: Option<u32>) -> Result<Vec<BackupStats>> {
        let stats_dir = self
            .stats_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("stats_dir must be configured for Json format"))?;

        let mut all_stats = Vec::new();

        if let Some(year) = year {
            // Read stats for a specific year
            let log_file = stats_dir.join(format!("{}-stats.jsonl", year));
            if log_file.exists() {
                let year_stats = self.read_stats_from_json_file(&log_file).await?;
                all_stats.extend(year_stats);
            }
        } else {
            // Read stats from all available years
            let mut entries = tokio::fs::read_dir(stats_dir).await.with_context(|| {
                format!("Failed to read stats directory: {}", stats_dir.display())
            })?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.is_file() {
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if file_name.ends_with("-stats.jsonl") {
                            match self.read_stats_from_json_file(&path).await {
                                Ok(year_stats) => all_stats.extend(year_stats),
                                Err(e) => {
                                    warn!("Failed to read stats from {}: {}", path.display(), e)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort by timestamp
        all_stats.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(all_stats)
    }

    /// Read statistics from a single JSON Lines file
    async fn read_stats_from_json_file(&self, file_path: &PathBuf) -> Result<Vec<BackupStats>> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .with_context(|| format!("Failed to read stats file: {}", file_path.display()))?;

        let mut stats = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<BackupStats>(line) {
                Ok(stat) => stats.push(stat),
                Err(e) => {
                    warn!(
                        "Failed to parse JSON on line {} in {}: {}",
                        line_num + 1,
                        file_path.display(),
                        e
                    );
                }
            }
        }

        Ok(stats)
    }

    /// Get summary statistics for a time period
    pub async fn get_summary(&self, days: Option<u32>) -> Result<StatsSummary> {
        let all_stats = self.read_stats(None).await?;

        let filtered_stats = if let Some(days) = days {
            let cutoff = Utc::now() - chrono::Duration::days(days as i64);
            all_stats
                .into_iter()
                .filter(|s| s.timestamp >= cutoff)
                .collect()
        } else {
            all_stats
        };

        if filtered_stats.is_empty() {
            return Ok(StatsSummary::default());
        }

        let total_backups = filtered_stats.len();
        let total_duration: u64 = filtered_stats.iter().map(|s| s.duration_seconds).sum();
        let avg_duration = total_duration / total_backups as u64;

        let first_backup = filtered_stats.first().unwrap().timestamp;
        let last_backup = filtered_stats.last().unwrap().timestamp;

        // Calculate total size progression (last snapshot size)
        let latest_total_size = filtered_stats
            .last()
            .map(|s| s.total_size.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        Ok(StatsSummary {
            total_backups,
            avg_duration_seconds: avg_duration,
            first_backup,
            last_backup,
            latest_total_size,
            period_days: days,
        })
    }

    /// Clean up old statistics files (only works for JsonLines format)
    pub async fn cleanup_old_stats(&self, keep_years: u32) -> Result<u32> {
        match self.format {
            StatsFormat::Logfile => self.cleanup_logfiles(keep_years).await,
            StatsFormat::Json => self.cleanup_json_lines_files(keep_years).await,
        }
    }

    /// Clean up old logfiles
    async fn cleanup_logfiles(&self, keep_years: u32) -> Result<u32> {
        let stats_dir = match self.stats_dir.as_ref() {
            Some(dir) => dir,
            None => {
                debug!("No stats directory configured, nothing to clean up");
                return Ok(0);
            }
        };

        let cutoff_date = Utc::now() - chrono::Duration::days((keep_years * 365) as i64);
        let profile_log = stats_dir.join(format!("{}.log", self.profile_name));

        if profile_log.exists() {
            let metadata = tokio::fs::metadata(&profile_log).await?;
            if let Ok(modified) = metadata.modified() {
                let modified_datetime = chrono::DateTime::<Utc>::from(modified);
                if modified_datetime < cutoff_date {
                    match tokio::fs::remove_file(&profile_log).await {
                        Ok(()) => {
                            debug!("Removed old log file: {}", profile_log.display());
                            return Ok(1);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to remove old log file {}: {}",
                                profile_log.display(),
                                e
                            );
                        }
                    }
                }
            }
        }

        Ok(0)
    }

    /// Clean up old JSON Lines statistics files
    async fn cleanup_json_lines_files(&self, keep_years: u32) -> Result<u32> {
        let stats_dir = match self.stats_dir.as_ref() {
            Some(dir) => dir,
            None => {
                debug!("No stats directory configured, nothing to clean up");
                return Ok(0);
            }
        };

        let current_year = Utc::now().year() as u32;
        let cutoff_year = current_year.saturating_sub(keep_years);

        let mut removed_count = 0;
        let mut entries = tokio::fs::read_dir(stats_dir)
            .await
            .with_context(|| format!("Failed to read stats directory: {}", stats_dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.ends_with("-stats.jsonl") {
                        // Extract year from filename
                        if let Some(year_str) = file_name.split('-').next() {
                            if let Ok(year) = year_str.parse::<u32>() {
                                if year <= cutoff_year {
                                    match tokio::fs::remove_file(&path).await {
                                        Ok(()) => {
                                            debug!("Removed old stats file: {}", path.display());
                                            removed_count += 1;
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to remove old stats file {}: {}",
                                                path.display(),
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(removed_count)
    }
}

#[derive(Debug, Clone)]
pub struct StatsSummary {
    pub total_backups: usize,
    pub avg_duration_seconds: u64,
    pub first_backup: chrono::DateTime<Utc>,
    pub last_backup: chrono::DateTime<Utc>,
    pub latest_total_size: String,
    pub period_days: Option<u32>,
}

impl Default for StatsSummary {
    fn default() -> Self {
        Self {
            total_backups: 0,
            avg_duration_seconds: 0,
            first_backup: Utc::now(),
            last_backup: Utc::now(),
            latest_total_size: "Unknown".to_string(),
            period_days: None,
        }
    }
}

impl std::fmt::Display for StatsSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.total_backups == 0 {
            return write!(f, "No backup statistics available");
        }

        let period_desc = match self.period_days {
            Some(days) => format!("Last {} days", days),
            None => "All time".to_string(),
        };

        write!(
            f,
            "Backup Statistics ({}):
  Total backups: {}
  Average duration: {}s ({} minutes)
  First backup: {}
  Last backup: {}
  Latest total size: {}",
            period_desc,
            self.total_backups,
            self.avg_duration_seconds,
            self.avg_duration_seconds / 60,
            self.first_backup.format("%Y-%m-%d %H:%M:%S"),
            self.last_backup.format("%Y-%m-%d %H:%M:%S"),
            self.latest_total_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_structured_logging() {
        let logger = StatsLogger::new(None, StatsFormat::Json, "test-profile".to_string());

        let stats = BackupStats {
            timestamp: Utc::now(),
            snapshot_id: "test123".to_string(),
            added_size: "1.0 GB".to_string(),
            removed_size: "0.5 GB".to_string(),
            total_size: "10.0 GB".to_string(),
            duration_seconds: 300,
        };

        // Should not error for structured logging
        logger.log_stats(&stats).await.unwrap();

        // Cannot read back from structured logging
        let read_stats = logger.read_stats(None).await.unwrap();
        assert_eq!(read_stats.len(), 0);
    }

    #[tokio::test]
    async fn test_json_lines_logging() {
        let temp_dir = TempDir::new().unwrap();
        let logger = StatsLogger::new(
            Some(temp_dir.path().to_path_buf()),
            StatsFormat::Json,
            "test-profile".to_string(),
        );

        let stats = BackupStats {
            timestamp: Utc::now(),
            snapshot_id: "test123".to_string(),
            added_size: "1.0 GB".to_string(),
            removed_size: "0.5 GB".to_string(),
            total_size: "10.0 GB".to_string(),
            duration_seconds: 300,
        };

        // Log stats
        logger.log_stats(&stats).await.unwrap();

        // Read stats back
        let read_stats = logger.read_stats(None).await.unwrap();
        assert_eq!(read_stats.len(), 1);
        assert_eq!(read_stats[0].snapshot_id, "test123");
    }

    #[tokio::test]
    async fn test_summary_generation() {
        let temp_dir = TempDir::new().unwrap();
        let logger = StatsLogger::new(
            Some(temp_dir.path().to_path_buf()),
            StatsFormat::Json,
            "test-profile".to_string(),
        );

        // Log multiple stats
        for i in 0..3 {
            let stats = BackupStats {
                timestamp: Utc::now() - chrono::Duration::hours(i),
                snapshot_id: format!("test{}", i),
                added_size: "1.0 GB".to_string(),
                removed_size: "0.5 GB".to_string(),
                total_size: "10.0 GB".to_string(),
                duration_seconds: 300 + i as u64,
            };
            logger.log_stats(&stats).await.unwrap();
        }

        let summary = logger.get_summary(None).await.unwrap();
        assert_eq!(summary.total_backups, 3);
        assert_eq!(summary.avg_duration_seconds, 301); // (300 + 301 + 302) / 3
    }

    #[tokio::test]
    async fn test_cleanup_old_stats() {
        let temp_dir = TempDir::new().unwrap();
        let logger = StatsLogger::new(
            Some(temp_dir.path().to_path_buf()),
            StatsFormat::Json,
            "test-profile".to_string(),
        );

        // Create some old stats files
        let old_file = temp_dir.path().join("2020-stats.jsonl");
        tokio::fs::write(&old_file, r#"{"timestamp":"2020-01-01T00:00:00Z","snapshot_id":"old","added_size":"1GB","removed_size":"0","total_size":"1GB","duration_seconds":100}"#).await.unwrap();

        let recent_file = temp_dir.path().join("2024-stats.jsonl");
        tokio::fs::write(&recent_file, r#"{"timestamp":"2024-01-01T00:00:00Z","snapshot_id":"recent","added_size":"1GB","removed_size":"0","total_size":"1GB","duration_seconds":100}"#).await.unwrap();

        // Cleanup files older than 3 years
        let removed = logger.cleanup_old_stats(3).await.unwrap();

        // Should remove the 2020 file but not the 2024 file
        assert_eq!(removed, 1);
        assert!(!old_file.exists());
        assert!(recent_file.exists());
    }

    #[tokio::test]
    async fn test_json_lines_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let logger = StatsLogger::new(
            Some(temp_dir.path().to_path_buf()),
            StatsFormat::Json,
            "test-profile".to_string(),
        );

        // Create a JSON Lines file with multiple entries
        let jsonl_file = temp_dir.path().join("2024-stats.jsonl");
        let content = r#"{"timestamp":"2024-01-01T10:00:00Z","snapshot_id":"abc123","added_size":"1.5 GB","removed_size":"0.2 GB","total_size":"10.3 GB","duration_seconds":180}
{"timestamp":"2024-01-01T11:00:00Z","snapshot_id":"def456","added_size":"0.8 GB","removed_size":"0.1 GB","total_size":"11.0 GB","duration_seconds":120}
{"timestamp":"2024-01-01T12:00:00Z","snapshot_id":"ghi789","added_size":"2.1 GB","removed_size":"0.3 GB","total_size":"12.8 GB","duration_seconds":240}"#;

        tokio::fs::write(&jsonl_file, content).await.unwrap();

        // Read the stats
        let stats = logger.read_stats(Some(2024)).await.unwrap();
        assert_eq!(stats.len(), 3);
        assert_eq!(stats[0].snapshot_id, "abc123");
        assert_eq!(stats[1].snapshot_id, "def456");
        assert_eq!(stats[2].snapshot_id, "ghi789");
        assert_eq!(stats[0].duration_seconds, 180);
        assert_eq!(stats[1].duration_seconds, 120);
        assert_eq!(stats[2].duration_seconds, 240);
    }

    #[tokio::test]
    async fn test_structured_logging_cleanup() {
        let logger = StatsLogger::new(None, StatsFormat::Json, "test-profile".to_string());

        // Should return 0 when no stats_dir is configured (nothing to clean up)
        let removed = logger.cleanup_old_stats(5).await.unwrap();
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn test_logfile_format() {
        let temp_dir = TempDir::new().unwrap();
        let logger = StatsLogger::new(
            Some(temp_dir.path().to_path_buf()),
            StatsFormat::Logfile,
            "test-profile".to_string(),
        );

        let stats = BackupStats {
            timestamp: Utc::now(),
            snapshot_id: "test123".to_string(),
            added_size: "1.0 GB".to_string(),
            removed_size: "0.5 GB".to_string(),
            total_size: "10.0 GB".to_string(),
            duration_seconds: 300,
        };

        // Log stats
        logger.log_stats(&stats).await.unwrap();

        // Check that log file was created
        let log_file = temp_dir.path().join("test-profile.log");
        assert!(log_file.exists());

        // Read and verify content
        let content = tokio::fs::read_to_string(&log_file).await.unwrap();
        assert!(content.contains("profile=test-profile"));
        assert!(content.contains("snapshot_id=test123"));
        assert!(content.contains("Backup completed"));
    }

    #[tokio::test]
    async fn test_dual_logging_json() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test json format with stats_dir - should log to both stdout and file
        let logger = StatsLogger::new(
            Some(temp_dir.path().to_path_buf()),
            StatsFormat::Json,
            "test-profile".to_string(),
        );

        let stats = BackupStats {
            timestamp: chrono::Utc::now(),
            snapshot_id: "test123".to_string(),
            added_size: "1.0 GB".to_string(),
            removed_size: "0.5 GB".to_string(),
            total_size: "10.0 GB".to_string(),
            duration_seconds: 300,
        };

        // Log stats - should write to both stdout and JSON file
        logger.log_stats(&stats).await.unwrap();

        // Check that JSON file was created
        let year = stats.timestamp.format("%Y").to_string();
        let json_file = temp_dir.path().join(format!("{}-stats.jsonl", year));
        assert!(json_file.exists());

        // Verify JSON content
        let content = tokio::fs::read_to_string(&json_file).await.unwrap();
        assert!(content.contains("test123"));
        assert!(content.contains("1.0 GB"));
    }

    #[tokio::test]
    async fn test_dual_logging_without_stats_dir() {
        // Test json format without stats_dir - should only log to stdout
        let logger = StatsLogger::new(None, StatsFormat::Json, "test-profile".to_string());

        let stats = BackupStats {
            timestamp: chrono::Utc::now(),
            snapshot_id: "test123".to_string(),
            added_size: "1.0 GB".to_string(),
            removed_size: "0.5 GB".to_string(),
            total_size: "10.0 GB".to_string(),
            duration_seconds: 300,
        };

        // Should not panic even without stats_dir
        logger.log_stats(&stats).await.unwrap();
    }
}
