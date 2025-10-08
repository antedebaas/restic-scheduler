# Restic Scheduler

Automatic restic backup scheduler with TOML-based configuration. A comprehensive solution for automating restic backups with support for multiple backup profiles, flexible scheduling, email and webhook notifications, backup statistics logging, repository health checks, and pre/post backup command execution.

## Features

- **Multiple Backup Profiles**: Configure different backup strategies for different data sets
- **Backend Support**: Backblaze B2 and S3-compatible storage backends
- **Flexible Configuration**: TOML-based configuration with environment variable support
- **Notification System**: Email and webhook notifications for backup success/failure
- **Statistics Logging**: Track backup performance and history with JSON, stdout, or log file output
- **Repository Health Checks**: Automated integrity verification
- **Pre/Post Commands**: Execute custom commands before and after backups
- **Retention Policies**: Automatic cleanup with configurable retention rules
- **Systemd Integration**: Native systemd service and timer support
- **Concurrent Operations**: Efficient multi-threaded backup operations
- **Process Management**: Skip backups if another restic process is running

## Installation

### From Source

```bash
git clone https://github.com/antedebaas/restic-scheduler.git
cd restic-scheduler
cargo build --release
sudo cp target/release/restic-scheduler /usr/local/bin/
```

### From Crates.io

```bash
cargo install restic-scheduler
```

### RPM Package (Fedora/RHEL)

RPM packages are available through COPR. The package includes systemd service files and proper user/group setup.

## Configuration

Copy the example configuration to `/etc/restic-scheduler/config.toml` and customize it for your needs:

```bash
sudo mkdir -p /etc/restic-scheduler
sudo cp config.example.toml /etc/restic-scheduler/config.toml
sudo chown restic-scheduler:restic-scheduler /etc/restic-scheduler/config.toml
sudo chmod 640 /etc/restic-scheduler/config.toml
```

### Configuration Structure

The configuration file supports:

- **Global Settings**: Verbosity, statistics format, and logging directory
- **Multiple Profiles**: Each with its own repository, paths, and settings
- **Backend Configuration**: B2 or S3-compatible storage settings
- **Retention Policies**: Hourly, daily, weekly, monthly, and yearly retention
- **Notifications**: Email SMTP and webhook configurations
- **Repository Checks**: Integrity verification settings

### Example Profile Configuration

```toml
[profiles.default]
repository = "b2:my-backup-bucket"
backup_paths = ["/home", "/etc", "/opt/important-data"]
backup_tags = ["daily-backup", "automated"]
encryption_password = "your-secure-password-here"

[profiles.default.backend.b2]
account_id = "your-b2-key-id"
account_key = "your-b2-application-key"
connections = 10

[profiles.default.retention]
hours = 24
days = 14
weeks = 8
months = 12
years = 5

[profiles.default.notifications.email]
notify_on_failure = true
smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_username = "your-email@gmail.com"
smtp_password = "your-app-password"
from = "your-email@gmail.com"
to = ["admin@example.com"]
use_tls = true
```

## Usage

### Basic Commands

```bash
# Perform a backup using the default profile
restic-scheduler backup

# Backup with specific profile
restic-scheduler --profile s3-backup backup

# Add random delay before backup (useful for cron jobs)
restic-scheduler backup --random-delay 300

# Skip backup if another restic process is running
restic-scheduler backup --skip-if-running

# Check repository integrity
restic-scheduler check

# Check all profiles
restic-scheduler check --all-profiles

# List snapshots
restic-scheduler snapshots

# Filter snapshots by tag
restic-scheduler snapshots --tag daily-backup

# Show repository statistics
restic-scheduler stats

# Show backup statistics
restic-scheduler backup-stats

# Show statistics for specific year
restic-scheduler backup-stats --year 2024

# Show summary for last 30 days
restic-scheduler backup-stats --days 30

# Clean up old statistics (keep last 2 years)
restic-scheduler backup-stats --cleanup-older-than 2

# Validate configuration
restic-scheduler validate-config

# List available profiles
restic-scheduler list-profiles

# Test repository connection
restic-scheduler test-connection

# Show system information
restic-scheduler info
```

### Configuration Options

```bash
# Custom configuration file
restic-scheduler --config /path/to/config.toml backup

# Increase verbosity
restic-scheduler -v backup          # Debug level
restic-scheduler -vv backup         # Trace level

# Specify profile
restic-scheduler --profile myprofile backup
```

## Systemd Integration

The package includes systemd service and timer units for automated scheduling:

### Service Files

- `restic-backup@.service` - Backup service template
- `restic-backup@.timer` - Backup timer template
- `restic-check@.service` - Repository check service template
- `restic-check@.timer` - Repository check timer template

### Enable Automated Backups

```bash
# Enable daily backups for default profile
sudo systemctl enable restic-backup@default.timer
sudo systemctl start restic-backup@default.timer

# Enable weekly repository checks
sudo systemctl enable restic-check@default.timer
sudo systemctl start restic-check@default.timer

# Check timer status
sudo systemctl list-timers restic-*

# View backup logs
sudo journalctl -u restic-backup@default.service -f
```

## Statistics and Monitoring

Restic Scheduler can log backup statistics in multiple formats:

### JSON Format
Statistics are saved as JSON Lines files in the configured directory:
```bash
tail -f /var/log/restic-scheduler/default.jsonl
```

### Stdout Format
Structured log events sent to stdout for log aggregation systems like ELK stack or Prometheus.

### Logfile Format
Structured log events saved to profile-named files in the statistics directory.

### Statistics Commands

```bash
# View recent backup statistics
restic-scheduler backup-stats

# Generate monthly report
restic-scheduler backup-stats --year 2024

# Performance summary for last week
restic-scheduler backup-stats --days 7

# Maintenance: clean old statistics
restic-scheduler backup-stats --cleanup-older-than 3
```

## Security Considerations

- Store encryption passwords securely using external commands
- Use application-specific passwords for email notifications
- Restrict configuration file permissions (640 recommended)
- Run as dedicated user (restic-scheduler)
- Regularly test backup restoration procedures
- Monitor backup success/failure notifications

## Dependencies

- **restic**: The restic backup program must be installed and available in PATH
- **systemd**: For automated scheduling (optional)
- **OpenSSL**: For TLS/SSL connections to storage backends

## Development

### Building from Source

```bash
git clone https://github.com/antedebaas/restic-scheduler.git
cd restic-scheduler
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Development Dependencies

```bash
# Install required system packages (Ubuntu/Debian)
sudo apt-get install libssl-dev pkg-config

# Install required system packages (Fedora/RHEL)
sudo dnf install openssl-devel pkgconfig
```

## License

This project is licensed under the GPL-3.0 License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Support

- Create an issue on GitHub for bug reports or feature requests
- Check the example configuration file for detailed setup instructions
- Review systemd service files for automation setup