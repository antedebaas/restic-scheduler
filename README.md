# Restic Scheduler

Automatic restic backup scheduler for automating backups.
It has support for multiple backup profiles, flexible scheduling, email, webhook, and command notifications, backup statistics logging, repository health checks, and pre/post backup command execution.

## Features

- **Multiple Backup Profiles**: Configure different backup strategies for different data sets
- **Backend Support**: Backblaze B2 and S3-compatible storage backends
- **Flexible Configuration**: TOML-based configuration with environment variable support
- **Notification System**: Email, webhook, and custom command notifications for backup success/failure
- **Statistics Logging**: Track backup performance and history with JSON output to stdout and optional file logging
- **Log Rotation**: Automatic log rotation with size limits, compression, and cleanup
- **Repository Health Checks**: Automated integrity verification
- **Pre/Post Commands**: Execute custom commands before and after backups
- **Retention Policies**: Automatic cleanup with configurable retention rules
- **Systemd Integration**: Native systemd service and timer support with capability-based privilege management
- **Sandboxing**: Landlock-based filesystem access restrictions for enhanced security
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

After installing the RPM package, you need to enable the systemd timers for your desired profiles:

```bash
# Enable daily backups for default profile
sudo systemctl enable restic-backup@default.timer
sudo systemctl start restic-backup@default.timer

# Enable weekly repository checks
sudo systemctl enable restic-check@default.timer
sudo systemctl start restic-check@default.timer
```

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

- **Global Settings**: Verbosity and logging directory
- **Multiple Profiles**: Each with its own repository, paths, and settings
- **Backend Configuration**: B2 or S3-compatible storage settings
- **Retention Policies**: Hourly, daily, weekly, monthly, and yearly retention
- **Notifications**: Email SMTP, webhook, and custom command configurations
- **Repository Checks**: Integrity verification settings

### Example Profile Configuration

#### Backblaze B2 Backend

```toml
[profiles.default]
backup_paths = ["/home", "/etc", "/opt/important-data"]
backup_tags = ["daily-backup", "automated"]
encryption_password = "your-secure-password-here"

[profiles.default.backend.b2]
account_id = "your-b2-key-id"
account_key = "your-b2-application-key"
bucket = "my-backup-bucket"
bucket_path = "restic"
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

#### S3-Compatible Backend

For S3-compatible services (MinIO, Wasabi, etc.), include the endpoint URL with `https://` or `http://` scheme:

```toml
[profiles.s3-backup]
backup_paths = ["/home", "/etc", "/var/www"]
backup_tags = ["s3-backup", "automated"]
encryption_password_command = "pass show restic/s3-backup"

[profiles.s3-backup.backend.s3]
access_key_id = "your-access-key-id"
secret_access_key = "your-secret-access-key"
region = "us-east-1"
endpoint = "https://s3.example.com"  # Include https:// or http:// scheme
bucket = "my-backup-bucket"
bucket_path = "restic"
path_style = true  # Required for most S3-compatible services

[profiles.s3-backup.retention]
days = 30
weeks = 12
months = 12
years = 10

[profiles.default.notifications.command]
notify_on_failure = true
command = "/usr/local/bin/notify-backup"
args = ["--profile", "default"]
timeout = 30
```

**Note**: For AWS S3, you can omit the `endpoint` field. For S3-compatible services, always include the full endpoint URL with the scheme (https:// or http://).

## Usage

### Basic Commands

```bash
# Perform a backup using the default profile
restic-scheduler backup

# Backup with specific profile
restic-scheduler --profile s3-backup backup

# Backups automatically skip if another restic process is running

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

# Unlock repository (remove stale locks)
restic-scheduler unlock

# Unlock all profiles
restic-scheduler unlock --all-profiles
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

- `restic-backup@.service` - Backup service template with capability-based privileges
- `restic-backup@.timer` - Backup timer template
- `restic-check@.service` - Repository check service template with capability-based privileges
- `restic-check@.timer` - Repository check timer template

#### Service Security Features

The systemd services implement security best practices:

- **Dedicated User**: Runs as `restic-scheduler` user (not root)
- **Linux Capabilities**: Uses minimal required capabilities:
  - `CAP_DAC_READ_SEARCH` - Read files regardless of DAC permissions
  - `CAP_FOWNER` - Override file ownership checks
  - `CAP_CHOWN` - Change file ownership when needed
- **Supplementary Groups**: Member of `backup` group for directory access
- **Filesystem Protection**: Limited filesystem access with specific read/write paths
- **Resource Limits**: CPU and I/O scheduling optimized for background operation

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

### Privilege Management

Restic Scheduler uses a capability-based privilege system when running as systemd services:

- **Service User**: Runs as `restic-scheduler` user with minimal privileges
- **Linux Capabilities**: Uses `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`, and `CAP_CHOWN` for file access
- **Supplementary Groups**: Automatically added to `backup` group for accessing protected directories
- **Secure Access**: Can read system files and backup directories without full root privileges

#### Granting Access to Protected Directories

To allow restic-scheduler to backup directories that require elevated privileges:

```bash
# Add directories to the backup group
sudo chgrp -R backup /path/to/protected/directory
sudo chmod -R g+r /path/to/protected/directory

# Or add specific users' directories to backup group
sudo usermod -a -G backup username
```

#### Manual Privilege Escalation

For interactive use, you may need to run with elevated privileges:

```bash
# Run backup with sudo if accessing protected paths
sudo restic-scheduler backup

# Or configure sudo rules for specific operations
echo "username ALL=(restic-scheduler) NOPASSWD: /usr/bin/restic-scheduler" | sudo tee /etc/sudoers.d/restic-scheduler
```

#### Systemd Service Configuration

The systemd services are configured with security hardening:

```bash
# View service configuration
systemctl cat restic-backup@default.service

# Check service status and capabilities
systemctl status restic-backup@default.service
sudo systemd-analyze security restic-backup@default.service

# Monitor service logs
journalctl -fu restic-backup@default.service
```

#### Troubleshooting Permissions

If backups fail due to permission issues:

```bash
# Check what the service user can access
sudo -u restic-scheduler ls -la /path/to/backup/directory

# Verify group membership
id restic-scheduler

# Check systemd service capabilities
systemctl show restic-backup@default.service | grep -i cap

# Test backup manually as service user
sudo -u restic-scheduler /usr/bin/restic-scheduler --profile default backup
```

## Statistics and Monitoring

Restic Scheduler logs backup statistics in JSON format:

### JSON Format
Statistics are always logged to stdout and optionally saved as JSON Lines files in the configured directory:
```bash
tail -f /var/log/restic-scheduler/default.jsonl
```

All statistics are output to stdout for log aggregation systems like ELK stack or Prometheus.

## Log Rotation

Restic-scheduler provides comprehensive log rotation capabilities to manage log file growth and prevent disk space issues.

### Built-in Log Rotation

Configure automatic log rotation in your `config.toml`:

```toml
[global]
stats_dir = "/var/log/restic-scheduler"

# Log rotation configuration
[global.log_rotation]
max_log_size_mb = 100        # Rotate when files exceed 100MB
max_log_age_days = 30        # Clean up files older than 30 days
compress_rotated = true      # Compress rotated files with gzip
max_rotated_files = 10       # Keep up to 10 rotated files per log
```

### Manual Cleanup

You can manually clean up old statistics files using the built-in command:

```bash
# Clean up statistics older than 2 years
restic-scheduler stats --cleanup-older-than 2
```

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

### Sandboxing

Restic Scheduler includes built-in sandboxing using Linux's Landlock security module (available since kernel 5.13). This feature restricts filesystem access to only the paths required for operation, providing defense-in-depth security.

#### How Sandboxing Works

When sandboxing is enabled (default), the application automatically restricts its own filesystem access to:

- **Read-write access**: `global.stats_dir` for writing backup statistics
- **Read-only access**: All `backup_paths` configured in profiles
- **Execute access**: 
  - Notification commands (`profiles.*.notifications.command`)
  - Pre-backup commands (`profiles.*.pre_backup_command`)
  - System binaries like `restic`
  - Common system paths (`/usr/bin`, `/lib`, `/etc`, etc.)

The sandboxing is applied after loading the configuration but before executing any operations, ensuring that even if a vulnerability is exploited, filesystem access remains restricted.

#### Feature Flag

Sandboxing is enabled by default but can be disabled at compile time if needed:

```bash
# Build without sandboxing
cargo build --release --no-default-features

# Build with sandboxing (default)
cargo build --release
```

#### Kernel Support

- **Supported**: Linux kernel 5.13 or later with Landlock enabled
- **Graceful fallback**: On older kernels or when Landlock is unavailable, the application continues to work normally without sandboxing restrictions
- **Status logging**: The application logs whether sandboxing is fully enforced, partially enforced, or not available

#### Security Best Practices

- Store encryption passwords securely using external commands
- Use application-specific passwords for email notifications
- Restrict configuration file permissions (640 recommended)
- Run as dedicated user (restic-scheduler) with minimal privileges
- Use Linux capabilities instead of running as root
- Configure backup group permissions for protected directories
- Keep kernel updated to ensure Landlock support
- Regularly test backup restoration procedures
- Monitor backup success/failure notifications
- Review systemd service security settings periodically

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
