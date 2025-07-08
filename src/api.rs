use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;


use tokio::time::{timeout, Duration, Instant};

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
    modification_time: Option<u64>,
    last_update_time: Option<u64>,
    updated_time: Option<u64>,
    alert_count: Option<u32>,
    alerts: Option<Vec<ApiAlert>>,
    hosts: Option<Vec<String>>,
    mitre_tactics: Option<Vec<String>>,
    mitre_techniques: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ApiAlert {
    alert_id: Option<String>,
    name: Option<String>,
    severity: Option<String>,
    category: Option<String>,
    source: Option<String>,
    host_name: Option<String>,
    endpoint_id: Option<String>,
    description: Option<String>,
    user_name: Option<String>,
    action_pretty: Option<String>,
    mitre_tactics: Option<Vec<String>>,
    mitre_techniques: Option<Vec<String>>,
    detection_timestamp: Option<u64>,
}

pub struct XdrClient {
    client: Client,
    config: Config,
    debug_enabled: bool,

    last_response_etag: Arc<std::sync::Mutex<Option<String>>>,
    last_successful_poll: Arc<std::sync::Mutex<Option<Instant>>>,
    consecutive_errors: Arc<AtomicU64>,
}

impl XdrClient {
    pub fn new(config: Config, debug_enabled: bool) -> Self {
        Self {
            client: Client::new(),
            config,
            debug_enabled,
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
        let request_data = HashMap::new();
        let request_body = GetIncidentsRequest { request_data };

        // Log POST content for debugging (only when --debug flag is enabled)
        if self.debug_enabled {
            self.safe_debug_log(format!(
                "\n=== POST CONTENT FOR INCIDENTS API ===\nURL: {}\nPOST Body: {}\nHeaders:\n  x-xdr-auth-id: {}\n  Authorization: {}...\n  Content-Type: application/json\n=====================================",
                url,
                serde_json::to_string_pretty(&request_body).unwrap_or_else(|_| "Failed to serialize".to_string()),
                self.config.api_key_id,
                if self.config.api_key_secret.len() >= 10 { 
                    &self.config.api_key_secret[..10]
                } else { 
                    &self.config.api_key_secret
                }
            ));
        }

        // Build request with conditional ETag caching
        let mut request_builder = self
            .client
            .post(&url)
            .header("x-xdr-auth-id", &self.config.api_key_id)
            .header("Authorization", &self.config.api_key_secret)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .json(&request_body);

        // Add If-None-Match header for caching if we have an ETag (with timeout)
        match timeout(Duration::from_millis(100), async {
            self.last_response_etag.lock()
        }).await {
            Ok(Ok(etag_guard)) => {
                if let Some(ref etag) = *etag_guard {
                    request_builder = request_builder.header("If-None-Match", etag);
                }
            }
            Ok(Err(_)) | Err(_) => {
                // Mutex poisoned or timeout - continue without ETag
            }
        }

        // Debug logging removed for production use
        
        let response = request_builder.send().await.map_err(|e| {
            self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
            // Network error logged internally
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
            let _error_body = response.text().await.unwrap_or_else(|_| "No response body".to_string());
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

        // Log raw incidents response for debugging (only when --debug flag is enabled)
        if self.debug_enabled {
            self.safe_debug_log(format!(
                "\n=== INCIDENTS API RAW RESPONSE ===\nResponse length: {} chars\nFirst 1000 chars: {}\n=== END INCIDENTS RESPONSE ===\n",
                response_text.len(),
                &response_text.chars().take(1000).collect::<String>()
            ));
        }

        // Parse JSON response
        let api_response: GetIncidentsResponse =
            serde_json::from_str(&response_text).map_err(|_e| {
                self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                anyhow!("Invalid response format received")
            })?;

        // Success - reset error counter and update last successful poll (with timeout)
        self.consecutive_errors.store(0, Ordering::Relaxed);
        match timeout(Duration::from_millis(100), async {
            self.last_successful_poll.lock()
        }).await {
            Ok(Ok(mut last_poll)) => {
                *last_poll = Some(Instant::now());
            }
            Ok(Err(_)) | Err(_) => {
                // Mutex poisoned or timeout - continue without updating timestamp
            }
        }

        // Convert incidents without fetching alerts initially for performance
        // Alert details will be fetched on-demand when user drills down
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



    pub fn get_poll_interval(&self) -> Duration {
        self.get_adaptive_poll_interval()
    }

    pub fn get_error_count(&self) -> u64 {
        self.consecutive_errors.load(Ordering::Relaxed)
    }

    fn convert_incident(&self, api_incident: ApiIncident) -> Incident {
        let creation_time = DateTime::from_timestamp(api_incident.creation_time as i64 / 1000, 0)
            .unwrap_or_else(Utc::now);

        // Check for update time fields in order of preference
        let last_updated = api_incident.modification_time
            .or(api_incident.last_update_time)
            .or(api_incident.updated_time)
            .and_then(|timestamp| DateTime::from_timestamp(timestamp as i64 / 1000, 0));

        // Convert any alerts that are included in the main response
        let alerts: Vec<Alert> = if let Some(api_alerts) = api_incident.alerts {
            // Only log when alerts are actually found to reduce noise
            if !api_alerts.is_empty() {
                eprintln!("DEBUG: Main incident response included {} alerts for incident {}", api_alerts.len(), api_incident.incident_id);
            }
            api_alerts.into_iter()
                .map(|api_alert| Alert {
                    name: api_alert.name.unwrap_or_else(|| "Unknown".to_string()),
                    severity: api_alert.severity.unwrap_or_else(|| api_incident.severity.clone()),
                    category: api_alert.category.unwrap_or_else(|| "Unknown".to_string()),
                    source: api_alert.source,
                    host_name: api_alert.host_name,
                    description: api_alert.description,
                    user_name: api_alert.user_name,
                    action_pretty: api_alert.action_pretty,
                    mitre_tactics: api_alert.mitre_tactics.unwrap_or_default(),
                    mitre_techniques: api_alert.mitre_techniques.unwrap_or_default(),
                })
                .collect()
        } else {
            Vec::new()
        };

        let mitre_tactics = api_incident.mitre_tactics.unwrap_or_default();
        let mitre_techniques = api_incident.mitre_techniques.unwrap_or_default();
        
        // MITRE data processing (production ready)

        // Extract description and count first to avoid borrow issues
        let description = api_incident.description.clone().unwrap_or_else(|| "".to_string());
        let alert_count = if let Some(api_count) = api_incident.alert_count {
            api_count // Use API count if available
        } else {
            // Extract count from description if API doesn't provide it
            if description.contains("along with") {
                // Parse "along with X other" patterns
                if description.contains("along with 2 other") {
                    3 // 1 + 2 others = 3 total
                } else if description.contains("along with 1 other") {
                    2 // 1 + 1 other = 2 total  
                } else if description.contains("along with") && description.contains("other") {
                    // Try to extract number
                    if let Some(num_str) = description.split("along with ").nth(1) {
                        if let Some(num_part) = num_str.split(" other").next() {
                            if let Ok(count) = num_part.trim().parse::<u32>() {
                                count + 1 // Add 1 for the main issue
                            } else {
                                1 // Default fallback
                            }
                        } else {
                            1
                        }
                    } else {
                        1
                    }
                } else {
                    1 // Single issue
                }
            } else {
                1 // Default to 1 if no pattern found
            }
        };

        Incident {
            id: api_incident.incident_id,
            status: api_incident.status,
            severity: api_incident.severity,
            description,
            creation_time,
            last_updated,
            alert_count,
            alerts,
            // Extract MITRE ATT&CK data from main incident response
            mitre_tactics,
            mitre_techniques,
        }
    }

    // Public function to get alerts for a specific incident on-demand
    pub async fn get_incident_alerts(&self, incident_id: &str) -> Result<Vec<Alert>> {
        
        let url = format!(
            "{}/public_api/v1/incidents/get_incident_extra_data/",
            self.config.tenant_url
        );

        let request_body = serde_json::json!({
            "request_data": {
                "incident_id": incident_id
            }
        });

        // Log POST content for debugging (only when --debug flag is enabled)
        if self.debug_enabled {
            self.safe_debug_log(format!(
                "\n=== POST CONTENT FOR INCIDENT EXTRA DATA API ===\nURL: {}\nPOST Body: {}\nHeaders:\n  x-xdr-auth-id: {}\n  Authorization: {}...\n  Content-Type: application/json\n=====================================",
                url,
                serde_json::to_string_pretty(&request_body).unwrap_or_else(|_| "Failed to serialize".to_string()),
                self.config.api_key_id,
                if self.config.api_key_secret.len() >= 10 { 
                    &self.config.api_key_secret[..10]
                } else { 
                    &self.config.api_key_secret
                }
            ));
        }


        
        let response = self
            .client
            .post(&url)
            .header("x-xdr-auth-id", &self.config.api_key_id)
            .header("Authorization", &self.config.api_key_secret)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(8))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| anyhow!("Alert request failed: {}", e))?;



        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!("Alert API request failed with status: {} - {}", status, error_body));
        }

        let response_text = response.text().await
            .map_err(|e| anyhow!("Failed to read incident extra data response: {}", e))?;
        
        // Parse the incident extra data API response
        let extra_data_response: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| anyhow!("Invalid incident extra data response format: {}", e))?;

        // Extract alerts from $.reply.alerts.data
        let alerts = if let Some(reply) = extra_data_response.get("reply") {
            if let Some(alerts_section) = reply.get("alerts") {
                if let Some(alerts_data) = alerts_section.get("data") {
                    if let Some(alerts_array) = alerts_data.as_array() {
                    let alerts: Vec<_> = alerts_array
                        .iter()
                        .map(|alert_value| Alert {
                            name: alert_value.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown Alert").to_string(),
                            severity: alert_value.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                            category: alert_value.get("category").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                            source: alert_value.get("source").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            host_name: alert_value.get("host_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            description: alert_value.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            user_name: alert_value.get("user_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            action_pretty: alert_value.get("action_pretty").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            mitre_tactics: alert_value.get("mitre_tactic_id_and_name")
                                .and_then(|v| v.as_str())
                                .map(|s| vec![s.to_string()])
                                .unwrap_or_default(),
                            mitre_techniques: alert_value.get("mitre_technique_id_and_name")
                                .and_then(|v| v.as_str())
                                .map(|s| vec![s.to_string()])
                                .unwrap_or_default(),
                        })
                        .collect();

                        alerts
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        Ok(alerts)
    }

    /// Safe debug logging helper with proper resource management
    fn safe_debug_log(&self, message: String) {
        if !self.debug_enabled {
            return;
        }

        // Use a separate task to handle file I/O with timeout to prevent blocking
        let _ = std::thread::spawn(move || {
            let timeout_duration = std::time::Duration::from_millis(500);
            let start = std::time::Instant::now();
            
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("debug_output.log") {
                Ok(mut file) => {
                    if start.elapsed() < timeout_duration {
                        let _ = writeln!(file, "{}", message);
                        let _ = file.flush(); // Ensure data is written
                    }
                }
                Err(_) => {
                    // Silent fail - don't let logging errors affect main operation
                }
            }
        });
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
