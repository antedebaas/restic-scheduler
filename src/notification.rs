use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::json;

use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::config::{EmailConfig, NotificationConfig, WebhookConfig};

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
            let should_notify_email = match message.success {
                true => email_config.notify_on_success,
                false => email_config.notify_on_failure,
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
            let should_notify_webhook = match message.success {
                true => webhook_config.notify_on_success,
                false => webhook_config.notify_on_failure,
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

        if notifications_sent == 0 {
            if let Some(error) = last_error {
                return Err(error);
            } else {
                warn!("No notification methods configured");
            }
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
                .with_context(|| format!("Invalid recipient email: {}", recipient))?;
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
            .timeout(Duration::from_secs(config.timeout))
            .build()
            .context("Failed to create HTTP client")?;

        let payload = self.format_webhook_payload(message);

        let mut request = match config.method.to_uppercase().as_str() {
            "GET" => client.get(&config.url),
            "POST" => client.post(&config.url).json(&payload),
            "PUT" => client.put(&config.url).json(&payload),
            "PATCH" => client.patch(&config.url).json(&payload),
            method => anyhow::bail!("Unsupported HTTP method: {}", method),
        };

        // Add custom headers
        for (key, value) in &config.headers {
            request = request.header(key, value);
        }

        let response = request
            .send()
            .await
            .context("Failed to send webhook request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Webhook request failed with status {}: {}", status, body);
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
        body.push_str(&format!("Status: {}\n", status));
        body.push_str(&format!(
            "Timestamp: {}\n",
            message.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        if let Some(duration) = message.duration {
            body.push_str(&format!("Duration: {}s\n", duration));
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

    /// Check if this is likely a Slack webhook
    fn is_slack_webhook(&self) -> bool {
        self.config
            .webhook
            .as_ref()
            .map(|w| w.url.contains("hooks.slack.com"))
            .unwrap_or(false)
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
            text.push_str(&format!(" ({}s)", duration));
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
    use crate::config::{EmailConfig, NotificationConfig, WebhookConfig};

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
        use std::collections::HashMap;
        WebhookConfig {
            notify_on_success: false,
            notify_on_failure: true,
            url: "https://example.com/webhook".to_string(),
            method: "POST".to_string(),
            headers: HashMap::new(),
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
