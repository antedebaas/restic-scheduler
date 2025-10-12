use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;

use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::config::{CommandConfig, EmailConfig, NotificationConfig, WebhookConfig};

#[derive(Debug, Clone)]
pub struct NotificationMessage {
    pub operation: String,
    pub success: bool,
    pub message: String,
    pub details: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub duration: Option<u64>,
}

pub struct NotificationSender {
    config: NotificationConfig,
    profile_name: String,
}

impl NotificationSender {
    pub fn new(config: NotificationConfig, profile_name: String) -> Self {
        Self {
            config,
            profile_name,
        }
    }

    /// Send notification based on configuration and event type
    pub async fn send_notification(&self, message: NotificationMessage) -> Result<()> {
        let mut notifications_sent = 0;
        let mut last_error = None;

        // Send email notification
        if let Some(ref email_config) = self.config.email {
            let should_notify_email = if message.success {
                email_config.notify_on_success
            } else {
                email_config.notify_on_failure
            };

            if should_notify_email {
                match self.send_email(email_config, &message).await {
                    Ok(()) => {
                        info!("Email notification sent successfully");
                        notifications_sent += 1;
                    }
                    Err(e) => {
                        error!("Failed to send email notification: {}", e);
                        last_error = Some(e);
                    }
                }
            } else {
                debug!(
                    "Email notification skipped for {} (success: {})",
                    message.operation, message.success
                );
            }
        }

        // Send webhook notification
        if let Some(ref webhook_config) = self.config.webhook {
            let should_notify_webhook = if message.success {
                webhook_config.notify_on_success
            } else {
                webhook_config.notify_on_failure
            };

            if should_notify_webhook {
                match self.send_webhook(webhook_config, &message).await {
                    Ok(()) => {
                        info!("Webhook notification sent successfully");
                        notifications_sent += 1;
                    }
                    Err(e) => {
                        error!("Failed to send webhook notification: {}", e);
                        last_error = Some(e);
                    }
                }
            } else {
                debug!(
                    "Webhook notification skipped for {} (success: {})",
                    message.operation, message.success
                );
            }
        }

        // Send command notification
        if let Some(ref command_config) = self.config.command {
            let should_notify_command = if message.success {
                command_config.notify_on_success
            } else {
                command_config.notify_on_failure
            };

            if should_notify_command {
                match self.send_command(command_config, &message).await {
                    Ok(()) => {
                        info!("Command notification executed successfully");
                        notifications_sent += 1;
                    }
                    Err(e) => {
                        error!("Failed to execute command notification: {}", e);
                        last_error = Some(e);
                    }
                }
            } else {
                debug!(
                    "Command notification skipped for {} (success: {})",
                    message.operation, message.success
                );
            }
        }

        if notifications_sent == 0 {
            if let Some(error) = last_error {
                return Err(error);
            }
            warn!("No notification methods configured");
        }

        Ok(())
    }

    /// Send email notification
    async fn send_email(&self, config: &EmailConfig, message: &NotificationMessage) -> Result<()> {
        use lettre::{
            message::Mailbox,
            transport::smtp::{
                authentication::Credentials,
                client::{Tls, TlsParameters},
            },
            AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
        };

        debug!("Sending email notification via {}", config.smtp_server);

        let subject = format!(
            "Restic {} {} - {}",
            message.operation,
            if message.success { "Success" } else { "Failed" },
            self.profile_name
        );

        let body = self.format_email_body(message);

        // Parse sender
        let from: Mailbox = config
            .from
            .parse()
            .with_context(|| format!("Invalid sender email: {}", config.from))?;

        // Build message with recipients
        let mut email_builder = Message::builder().from(from).subject(subject);

        // Add recipients
        for recipient in &config.to {
            let to: Mailbox = recipient
                .parse()
                .with_context(|| format!("Invalid recipient email: {recipient}"))?;
            email_builder = email_builder.to(to);
        }

        let email = email_builder
            .body(body)
            .context("Failed to build email message")?;

        // Configure SMTP transport
        let mut transport_builder =
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_server)
                .port(config.smtp_port)
                .credentials(Credentials::new(
                    config.smtp_username.clone(),
                    config.smtp_password.clone(),
                ));

        if config.use_tls {
            let tls_parameters = TlsParameters::builder(config.smtp_server.clone())
                .build()
                .context("Failed to build TLS parameters")?;
            transport_builder = transport_builder.tls(Tls::Required(tls_parameters));
        }

        let transport = transport_builder.build();

        // Send email with timeout
        timeout(Duration::from_secs(30), transport.send(email))
            .await
            .context("Email send timeout")?
            .context("Failed to send email")?;

        Ok(())
    }

    /// Send webhook notification
    async fn send_webhook(
        &self,
        config: &WebhookConfig,
        message: &NotificationMessage,
    ) -> Result<()> {
        debug!("Sending webhook notification to {}", config.url);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(u64::from(config.timeout)))
            .build()
            .context("Failed to create HTTP client")?;

        let payload = self.format_webhook_payload(message);

        // Substitute ${report} variables in URL
        let url = self.substitute_report_variables(&config.url, message);

        let mut request = match config.method.to_uppercase().as_str() {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&payload),
            "PUT" => client.put(&url).json(&payload),
            "PATCH" => client.patch(&url).json(&payload),
            method => anyhow::bail!("Unsupported HTTP method: {method}"),
        };

        // Add custom headers with ${report} variable substitution
        for (key, value) in &config.headers {
            let substituted_value = self.substitute_report_variables(value, message);
            request = request.header(key, substituted_value);
        }

        let response = request
            .send()
            .await
            .context("Failed to send webhook request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Webhook request failed with status {status}: {body}");
        }

        Ok(())
    }

    /// Format email body
    fn format_email_body(&self, message: &NotificationMessage) -> String {
        let status = if message.success { "SUCCESS" } else { "FAILED" };
        let mut body = format!("Restic {} Report\n", message.operation.to_uppercase());
        body.push_str(&"=".repeat(50));
        body.push('\n');
        body.push_str(&format!("Profile: {}\n", self.profile_name));
        body.push_str(&format!("Operation: {}\n", message.operation));
        body.push_str(&format!("Status: {status}\n"));
        body.push_str(&format!(
            "Timestamp: {}",
            message.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        if let Some(duration) = message.duration {
            body.push_str(&format!("Duration: {duration}s\n"));
        }

        body.push('\n');
        body.push_str("Message:\n");
        body.push_str(&message.message);
        body.push('\n');

        if let Some(ref details) = message.details {
            body.push('\n');
            body.push_str("Details:\n");
            body.push_str(details);
            body.push('\n');
        }

        body.push('\n');
        body.push_str("--\n");
        body.push_str("Sent by restic-scheduler\n");

        body
    }

    /// Format webhook payload
    fn format_webhook_payload(&self, message: &NotificationMessage) -> serde_json::Value {
        let mut payload = json!({
            "profile": self.profile_name,
            "operation": message.operation,
            "success": message.success,
            "message": message.message,
            "timestamp": message.timestamp.to_rfc3339(),
            "service": "restic-scheduler"
        });

        if let Some(duration) = message.duration {
            payload["duration_seconds"] = json!(duration);
        }

        if let Some(ref details) = message.details {
            payload["details"] = json!(details);
        }

        // Add Slack-compatible formatting if this looks like a Slack webhook
        if self.is_slack_webhook() {
            payload = self.format_slack_payload(message);
        }

        payload
    }

    /// Sanitize report data for safe inclusion in notifications
    fn sanitize_report_data(&self, data: &str) -> String {
        // Remove potentially dangerous characters and limit length
        let mut sanitized = data
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .take(10000) // Limit to 10KB
            .collect::<String>();

        // Replace shell-dangerous characters in command contexts
        // Note: Order matters to avoid double-escaping
        sanitized = sanitized.replace('\\', "\\\\"); // Must be first
        sanitized = sanitized.replace('`', "'");
        sanitized = sanitized.replace('$', "\\$");
        sanitized = sanitized.replace('"', "\\\"");

        sanitized
    }

    /// Substitute ${report} variables in a string
    fn substitute_report_variables(&self, template: &str, message: &NotificationMessage) -> String {
        if let Some(ref details) = message.details {
            let sanitized_report = self.sanitize_report_data(details);
            template.replace("${report}", &sanitized_report)
        } else {
            template.replace("${report}", "No details available")
        }
    }

    /// Execute command notification
    async fn send_command(
        &self,
        config: &CommandConfig,
        message: &NotificationMessage,
    ) -> Result<()> {
        use std::process::Stdio;
        use tokio::process::Command;

        debug!("Executing command notification: {}", config.command);

        // Substitute ${report} variables in command
        let command = self.substitute_report_variables(&config.command, message);
        let mut cmd = Command::new(&command);

        // Substitute ${report} variables in arguments
        let substituted_args: Vec<String> = config
            .args
            .iter()
            .map(|arg| self.substitute_report_variables(arg, message))
            .collect();

        // Add arguments
        cmd.args(&substituted_args);

        // Set standard environment variables with notification data
        cmd.env("RESTIC_PROFILE", &self.profile_name)
            .env("RESTIC_OPERATION", &message.operation)
            .env(
                "RESTIC_SUCCESS",
                if message.success { "true" } else { "false" },
            )
            .env("RESTIC_MESSAGE", &message.message)
            .env("RESTIC_TIMESTAMP", message.timestamp.to_rfc3339())
            .env("RESTIC_SERVICE", "restic-scheduler");

        if let Some(duration) = message.duration {
            cmd.env("RESTIC_DURATION", duration.to_string());
        }

        if let Some(ref details) = message.details {
            cmd.env("RESTIC_DETAILS", details);
        }

        // Configure stdio
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Execute command with timeout
        let output = timeout(Duration::from_secs(u64::from(config.timeout)), cmd.output())
            .await
            .context("Command execution timeout")?
            .context("Failed to execute command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            anyhow::bail!(
                "Command failed with exit code {:?}. stdout: {}, stderr: {}",
                output.status.code(),
                stdout,
                stderr
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            debug!("Command output: {}", stdout.trim());
        }

        Ok(())
    }

    /// Check if this is likely a Slack webhook
    fn is_slack_webhook(&self) -> bool {
        self.config
            .webhook
            .as_ref()
            .is_some_and(|w| w.url.contains("hooks.slack.com"))
    }

    /// Format payload specifically for Slack
    fn format_slack_payload(&self, message: &NotificationMessage) -> serde_json::Value {
        let color = if message.success { "good" } else { "danger" };
        let status_emoji = if message.success {
            ":white_check_mark:"
        } else {
            ":x:"
        };

        let mut text = format!(
            "{} *{}* {} for profile `{}`",
            status_emoji,
            message.operation.to_uppercase(),
            if message.success {
                "completed successfully"
            } else {
                "failed"
            },
            self.profile_name
        );

        if let Some(duration) = message.duration {
            text.push_str(&format!(" ({duration}s)"));
        }

        let mut fields = vec![json!({
            "title": "Message",
            "value": message.message,
            "short": false
        })];

        if let Some(ref details) = message.details {
            fields.push(json!({
                "title": "Details",
                "value": format!("```{}```", details),
                "short": false
            }));
        }

        json!({
            "attachments": [{
                "color": color,
                "text": text,
                "fields": fields,
                "footer": "restic-scheduler",
                "ts": message.timestamp.timestamp()
            }]
        })
    }
}

/// Create notification message for backup operation
pub fn create_backup_notification(
    success: bool,
    message: String,
    details: Option<String>,
    duration: Option<u64>,
) -> NotificationMessage {
    NotificationMessage {
        operation: "backup".to_string(),
        success,
        message,
        details,
        timestamp: Utc::now(),
        duration,
    }
}

/// Create notification message for check operation
pub fn create_check_notification(
    success: bool,
    message: String,
    details: Option<String>,
    duration: Option<u64>,
) -> NotificationMessage {
    NotificationMessage {
        operation: "check".to_string(),
        success,
        message,
        details,
        timestamp: Utc::now(),
        duration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CommandConfig, EmailConfig, NotificationConfig, WebhookConfig};

    fn create_test_email_config() -> EmailConfig {
        EmailConfig {
            notify_on_success: false,
            notify_on_failure: true,
            smtp_server: "smtp.example.com".to_string(),
            smtp_port: 587,
            smtp_username: "test@example.com".to_string(),
            smtp_password: "password".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            use_tls: true,
        }
    }

    fn create_test_webhook_config() -> WebhookConfig {
        WebhookConfig {
            notify_on_success: false,
            notify_on_failure: true,
            url: "https://example.com/webhook".to_string(),
            method: "POST".to_string(),
            headers: std::collections::HashMap::new(),
            timeout: 30,
        }
    }

    fn create_test_command_config() -> CommandConfig {
        CommandConfig {
            notify_on_success: false,
            notify_on_failure: true,
            command: "/bin/echo".to_string(),
            args: vec!["notification".to_string()],
            timeout: 30,
        }
    }

    fn create_test_message() -> NotificationMessage {
        NotificationMessage {
            operation: "backup".to_string(),
            success: true,
            message: "Backup completed successfully".to_string(),
            details: Some("Added: 1.0 GB\nRemoved: 0.5 GB".to_string()),
            timestamp: Utc::now(),
            duration: Some(300),
        }
    }

    #[test]
    fn test_format_email_body() {
        let config = NotificationConfig {
            email: Some(create_test_email_config()),
            webhook: None,
            command: None,
        };

        let sender = NotificationSender::new(config, "test-profile".to_string());
        let message = create_test_message();
        let body = sender.format_email_body(&message);

        assert!(body.contains("SUCCESS"));
        assert!(body.contains("test-profile"));
        assert!(body.contains("backup"));
        assert!(body.contains("Backup completed successfully"));
        assert!(body.contains("Added: 1.0 GB"));
    }

    #[test]
    fn test_format_webhook_payload() {
        let config = NotificationConfig {
            email: None,
            webhook: Some(create_test_webhook_config()),
            command: None,
        };

        let sender = NotificationSender::new(config, "test-profile".to_string());
        let message = create_test_message();
        let payload = sender.format_webhook_payload(&message);

        assert_eq!(payload["profile"], "test-profile");
        assert_eq!(payload["operation"], "backup");
        assert_eq!(payload["success"], true);
        assert_eq!(payload["duration_seconds"], 300);
    }

    #[test]
    fn test_slack_payload_formatting() {
        let mut webhook_config = create_test_webhook_config();
        webhook_config.url = "https://hooks.slack.com/services/test".to_string();

        let config = NotificationConfig {
            email: None,
            webhook: Some(webhook_config),
            command: None,
        };

        let sender = NotificationSender::new(config, "test-profile".to_string());
        let message = create_test_message();
        let payload = sender.format_slack_payload(&message);

        assert!(payload["attachments"].is_array());
        let attachment = &payload["attachments"][0];
        assert_eq!(attachment["color"], "good");
        assert!(attachment["text"]
            .as_str()
            .unwrap()
            .contains(":white_check_mark:"));
    }

    #[test]
    fn test_notification_filtering() {
        let config = NotificationConfig {
            email: None,
            webhook: None,
            command: None,
        };

        let _sender = NotificationSender::new(config, "test".to_string());

        // Should not notify on success
        let _success_message = create_test_message();
        // This would need async test framework to actually test

        // Should notify on failure
        let mut failure_message = create_test_message();
        failure_message.success = false;
        // This would need async test framework to actually test
    }

    #[test]
    fn test_command_config_creation() {
        let config = create_test_command_config();
        assert_eq!(config.command, "/bin/echo");
        assert_eq!(config.args, vec!["notification"]);
        assert_eq!(config.timeout, 30);
        assert!(!config.notify_on_success);
        assert!(config.notify_on_failure);
    }

    #[test]
    fn test_sanitize_report_data() {
        let config = NotificationConfig {
            email: None,
            webhook: None,
            command: None,
        };

        let sender = NotificationSender::new(config, "test".to_string());

        // Test normal data
        let normal_data = "Added: 1.5 GB\nRemoved: 0.2 GB";
        let sanitized = sender.sanitize_report_data(normal_data);
        assert_eq!(sanitized, "Added: 1.5 GB\nRemoved: 0.2 GB");

        // Test dangerous characters
        let dangerous_data = "echo `rm -rf /`; $USER \"quoted\" \\backslash";
        let sanitized = sender.sanitize_report_data(dangerous_data);
        assert_eq!(
            sanitized,
            "echo 'rm -rf /'; \\$USER \\\"quoted\\\" \\\\backslash"
        );

        // Test very long data (should be truncated)
        let long_data = "x".repeat(20000);
        let sanitized = sender.sanitize_report_data(&long_data);
        assert_eq!(sanitized.len(), 10000);
    }

    #[test]
    fn test_substitute_report_variables() {
        let config = NotificationConfig {
            email: None,
            webhook: None,
            command: None,
        };

        let sender = NotificationSender::new(config, "test".to_string());

        let mut message = create_test_message();
        message.details = Some("Backup stats: 1.5 GB added".to_string());

        // Test substitution with details
        let template = "Command with ${report} data";
        let result = sender.substitute_report_variables(template, &message);
        assert_eq!(result, "Command with Backup stats: 1.5 GB added data");

        // Test substitution without details
        message.details = None;
        let result = sender.substitute_report_variables(template, &message);
        assert_eq!(result, "Command with No details available data");

        // Test no substitution needed
        let template = "Command without variables";
        let result = sender.substitute_report_variables(template, &message);
        assert_eq!(result, "Command without variables");
    }

    #[test]
    fn test_create_notification_functions() {
        let backup_notif =
            create_backup_notification(true, "Backup done".to_string(), None, Some(120));

        assert_eq!(backup_notif.operation, "backup");
        assert!(backup_notif.success);
        assert_eq!(backup_notif.duration, Some(120));

        let check_notif = create_check_notification(
            false,
            "Check failed".to_string(),
            Some("Error details".to_string()),
            None,
        );

        assert_eq!(check_notif.operation, "check");
        assert!(!check_notif.success);
        assert_eq!(check_notif.details, Some("Error details".to_string()));
    }
}
