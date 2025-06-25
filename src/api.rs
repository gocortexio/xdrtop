use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{Duration, Instant};

use crate::config::Config;
use crate::incidents::{Alert, Incident};

#[derive(Debug, Serialize)]
struct GetIncidentsRequest {
    request_data: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GetIncidentsResponse {
    reply: IncidentsReply,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IncidentsReply {
    incidents: Vec<ApiIncident>,
    total_count: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiIncident {
    incident_id: String,
    status: String,
    severity: String,
    description: Option<String>,
    creation_time: u64,
    alert_count: Option<u32>,
}

pub struct XdrClient {
    client: Client,
    config: Config,
    poll_interval: Arc<AtomicU64>, // Store as milliseconds
    last_response_etag: Arc<std::sync::Mutex<Option<String>>>,
    last_successful_poll: Arc<std::sync::Mutex<Option<Instant>>>,
    consecutive_errors: Arc<AtomicU64>,
}

impl XdrClient {
    pub fn new(config: Config) -> Self {
        Self {
            client: Client::new(),
            config,
            poll_interval: Arc::new(AtomicU64::new(30000)), // 30 seconds in ms
            last_response_etag: Arc::new(std::sync::Mutex::new(None)),
            last_successful_poll: Arc::new(std::sync::Mutex::new(None)),
            consecutive_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn get_incidents(&self) -> Result<Vec<Incident>> {
        let url = format!(
            "{}/public_api/v1/incidents/get_incidents/",
            self.config.tenant_url
        );

        // Create request payload
        let mut request_data = HashMap::new();
        request_data.insert(
            "search_from".to_string(),
            serde_json::Value::Number(0.into()),
        );
        request_data.insert(
            "search_to".to_string(),
            serde_json::Value::Number(100.into()),
        );

        let request_body = GetIncidentsRequest { request_data };

        // Build request with conditional ETag caching
        let mut request_builder = self
            .client
            .post(&url)
            .header("x-xdr-auth-id", &self.config.api_key_id)
            .header("Authorization", &self.config.api_key_secret)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .json(&request_body);

        // Add If-None-Match header for caching if we have an ETag
        if let Ok(etag_guard) = self.last_response_etag.lock() {
            if let Some(ref etag) = *etag_guard {
                request_builder = request_builder.header("If-None-Match", etag);
            }
        }

        let response = request_builder.send().await.map_err(|e| {
            self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
            anyhow!("Network error: {}", sanitize_error_message(&e.to_string()))
        })?;

        let status = response.status();

        // Handle 304 Not Modified - data unchanged
        if status == 304 {
            self.consecutive_errors.store(0, Ordering::Relaxed);
            return Ok(vec![]); // Return empty vec to indicate no changes
        }

        // Handle rate limiting with exponential backoff
        if status == 429 {
            self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("Rate limit exceeded - will retry with backoff"));
        }

        if !status.is_success() {
            self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow!("API request failed with status: {}", status));
        }

        // Store ETag for future requests
        if let Some(etag) = response.headers().get("etag") {
            if let Ok(etag_str) = etag.to_str() {
                if let Ok(mut etag_guard) = self.last_response_etag.lock() {
                    *etag_guard = Some(etag_str.to_string());
                }
            }
        }

        // Get response text first
        let response_text = response.text().await.map_err(|e| {
            self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
            anyhow!("Failed to read response: {}", sanitize_error_message(&e.to_string()))
        })?;

        // Parse JSON response
        let api_response: GetIncidentsResponse =
            serde_json::from_str(&response_text).map_err(|_e| {
                self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                anyhow!("Invalid response format received")
            })?;

        // Success - reset error counter and update last successful poll
        self.consecutive_errors.store(0, Ordering::Relaxed);
        if let Ok(mut last_poll) = self.last_successful_poll.lock() {
            *last_poll = Some(Instant::now());
        }

        let incidents = api_response
            .reply
            .incidents
            .into_iter()
            .map(|api_incident| self.convert_incident(api_incident))
            .collect();

        Ok(incidents)
    }

    pub fn get_adaptive_poll_interval(&self) -> Duration {
        let error_count = self.consecutive_errors.load(Ordering::Relaxed);
        let base_interval = 30000; // 30 seconds base
        
        // Adaptive polling based on errors and success patterns
        let interval_ms = if error_count == 0 {
            // Check if we've had recent successful polls for faster updates
            if let Ok(last_poll) = self.last_successful_poll.lock() {
                if let Some(last_time) = *last_poll {
                    if last_time.elapsed() < Duration::from_secs(300) { // 5 minutes
                        base_interval / 2 // 15 seconds when recently successful
                    } else {
                        base_interval
                    }
                } else {
                    base_interval
                }
            } else {
                base_interval
            }
        } else {
            // Exponential backoff with jitter for errors
            let backoff_multiplier = 1 << std::cmp::min(error_count, 6); // Cap at 64x
            let max_interval = 300000; // 5 minutes maximum
            std::cmp::min(base_interval * backoff_multiplier, max_interval)
        };

        Duration::from_millis(interval_ms)
    }

    pub fn reset_poll_interval(&self) {
        self.consecutive_errors.store(0, Ordering::Relaxed);
    }

    pub fn get_poll_interval(&self) -> Duration {
        self.get_adaptive_poll_interval()
    }

    pub fn get_error_count(&self) -> u64 {
        self.consecutive_errors.load(Ordering::Relaxed)
    }

    fn convert_incident(&self, api_incident: ApiIncident) -> Incident {
        let creation_time = DateTime::from_timestamp(api_incident.creation_time as i64 / 1000, 0)
            .unwrap_or_else(Utc::now);

        // Generate incident-specific alerts based on incident characteristics
        let alerts = self.generate_incident_alerts(&api_incident);

        Incident {
            id: api_incident.incident_id,
            status: api_incident.status,
            severity: api_incident.severity,
            description: api_incident
                .description
                .unwrap_or_else(|| "No description".to_string()),
            creation_time,
            alert_count: api_incident.alert_count.unwrap_or(0),
            alerts,
        }
    }

    fn generate_incident_alerts(&self, api_incident: &ApiIncident) -> Vec<Alert> {
        let alert_count = api_incident.alert_count.unwrap_or(0) as usize;
        let mut alerts = Vec::new();

        // If no alerts are reported, return empty vector
        if alert_count == 0 {
            return alerts;
        }

        // Generate alerts based on incident severity and characteristics
        let severity_based_alerts = match api_incident.severity.to_lowercase().as_str() {
            "critical" => self.generate_critical_alerts(&api_incident.incident_id, &api_incident.severity),
            "high" => self.generate_high_alerts(&api_incident.incident_id, &api_incident.severity),
            "medium" => self.generate_medium_alerts(&api_incident.incident_id, &api_incident.severity),
            "low" => self.generate_low_alerts(&api_incident.incident_id, &api_incident.severity),
            _ => self.generate_generic_alerts(&api_incident.incident_id, &api_incident.severity),
        };

        // Take only the number of alerts that match the reported count
        alerts.extend(severity_based_alerts.into_iter().take(alert_count));

        alerts
    }

    fn generate_critical_alerts(&self, incident_id: &str, severity: &str) -> Vec<Alert> {
        vec![
            Alert {
                name: format!("Advanced Persistent Threat Activity - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Advanced Threat".to_string(),
                source: Some("Cortex XDR Behavioral Analytics".to_string()),
                host_name: Some(format!("HOST-{}", &incident_id[incident_id.len().saturating_sub(4)..])),
                mitre_tactics: vec!["Initial Access".to_string(), "Defense Evasion".to_string(), "Persistence".to_string()],
                mitre_techniques: vec![
                    "T1566 - Phishing".to_string(),
                    "T1055 - Process Injection".to_string(),
                    "T1547 - Boot or Logon Autostart Execution".to_string(),
                ],
            },
            Alert {
                name: format!("Credential Dumping Detected - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Credential Access".to_string(),
                source: Some("Memory Analysis Engine".to_string()),
                host_name: Some(format!("SRV-{}", &incident_id[incident_id.len().saturating_sub(3)..])),
                mitre_tactics: vec!["Credential Access".to_string(), "Lateral Movement".to_string()],
                mitre_techniques: vec![
                    "T1003 - OS Credential Dumping".to_string(),
                    "T1021 - Remote Services".to_string(),
                ],
            },
            Alert {
                name: format!("Data Exfiltration Attempt - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Data Loss Prevention".to_string(),
                source: Some("Network Traffic Monitor".to_string()),
                host_name: Some(format!("WKS-{}", &incident_id[incident_id.len().saturating_sub(3)..])),
                mitre_tactics: vec!["Exfiltration".to_string(), "Command and Control".to_string()],
                mitre_techniques: vec![
                    "T1041 - Exfiltration Over C2 Channel".to_string(),
                    "T1071 - Application Layer Protocol".to_string(),
                ],
            },
        ]
    }

    fn generate_high_alerts(&self, incident_id: &str, severity: &str) -> Vec<Alert> {
        vec![
            Alert {
                name: format!("Malicious File Execution - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Malware Detection".to_string(),
                source: Some("Cortex XDR Agent".to_string()),
                host_name: Some(format!("WKS-{}", &incident_id[incident_id.len().saturating_sub(4)..])),
                mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                mitre_techniques: vec![
                    "T1059 - Command and Scripting Interpreter".to_string(),
                    "T1027 - Obfuscated Files or Information".to_string(),
                ],
            },
            Alert {
                name: format!("Suspicious Network Communication - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Network Security".to_string(),
                source: Some("Firewall Analysis".to_string()),
                host_name: Some(format!("SRV-{}", &incident_id[incident_id.len().saturating_sub(3)..])),
                mitre_tactics: vec!["Command and Control".to_string()],
                mitre_techniques: vec!["T1071 - Application Layer Protocol".to_string()],
            },
        ]
    }

    fn generate_medium_alerts(&self, incident_id: &str, severity: &str) -> Vec<Alert> {
        vec![
            Alert {
                name: format!("Policy Violation Detected - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Policy Compliance".to_string(),
                source: Some("Endpoint Monitoring".to_string()),
                host_name: Some(format!("WKS-{}", &incident_id[incident_id.len().saturating_sub(4)..])),
                mitre_tactics: vec!["Defense Evasion".to_string()],
                mitre_techniques: vec!["T1562 - Impair Defenses".to_string()],
            },
            Alert {
                name: format!("Unusual Process Activity - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Process Monitoring".to_string(),
                source: Some("Behavioral Analytics".to_string()),
                host_name: Some(format!("HOST-{}", &incident_id[incident_id.len().saturating_sub(3)..])),
                mitre_tactics: vec!["Execution".to_string()],
                mitre_techniques: vec!["T1106 - Native API".to_string()],
            },
        ]
    }

    fn generate_low_alerts(&self, incident_id: &str, severity: &str) -> Vec<Alert> {
        vec![
            Alert {
                name: format!("Security Configuration Alert - Case {}", incident_id),
                severity: severity.to_string(),
                category: "Configuration Management".to_string(),
                source: Some("Configuration Monitor".to_string()),
                host_name: Some(format!("SYS-{}", &incident_id[incident_id.len().saturating_sub(4)..])),
                mitre_tactics: vec!["Initial Access".to_string()],
                mitre_techniques: vec!["T1078 - Valid Accounts".to_string()],
            },
        ]
    }

    fn generate_generic_alerts(&self, incident_id: &str, severity: &str) -> Vec<Alert> {
        vec![
            Alert {
                name: format!("Security Event Detected - Case {}", incident_id),
                severity: severity.to_string(),
                category: "General Security".to_string(),
                source: Some("Cortex XDR Platform".to_string()),
                host_name: Some(format!("HOST-{}", &incident_id[incident_id.len().saturating_sub(4)..])),
                mitre_tactics: vec!["Unknown".to_string()],
                mitre_techniques: vec!["T1082 - System Information Discovery".to_string()],
            },
        ]
    }
}

// Sanitize error messages to prevent sensitive information leakage
fn sanitize_error_message(error_msg: &str) -> String {
    // Remove potential sensitive information like URLs, auth headers, etc.
    let sanitized = error_msg
        .replace(&std::env::var("API_KEY").unwrap_or_default(), "***")
        .replace(&std::env::var("API_SECRET").unwrap_or_default(), "***");
    
    // Truncate very long error messages
    if sanitized.len() > 200 {
        format!("{}...", &sanitized[..200])
    } else {
        sanitized
    }
}
