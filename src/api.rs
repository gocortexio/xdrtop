// XDRTop API Module
// Cortex XDR Cases and Issues API client with typed requests, incremental sync, and intelligent caching
// Version 2.0.4 - Fixed drill-down issue fetch using issue_ids filter
// Following British English conventions throughout

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use std::collections::HashSet;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{Duration, Instant};

use crate::config::Config;
use crate::cases::{IssueDetail, Case};
use crate::types::{
    ApiCase, ApiIssue, CaseSearchRequestData, GetCasesRequest, GetCasesResponse,
    GetIssuesRequest, GetIssuesResponse, IssueSearchRequestData,
};

// ----------------------------------------------------------------------------
// XDR Client - Main API client with caching and sync
// ----------------------------------------------------------------------------

pub struct XdrClient {
    client: Client,
    config: Config,
    debug_enabled: bool,
    last_successful_poll: Arc<std::sync::Mutex<Option<Instant>>>,
    consecutive_errors: Arc<AtomicU64>,

    // Sync cursor - stores last modification_time
    sync_cursor: Arc<std::sync::Mutex<Option<u64>>>,

    // Performance caching for paginated results
    cached_cases: Arc<std::sync::Mutex<Option<Vec<Case>>>>,
    cache_timestamp: Arc<std::sync::Mutex<Option<Instant>>>,
    cache_duration: Duration,

    // Stale threshold for forcing full sync (10 minutes)
    #[allow(dead_code)]
    stale_threshold_secs: u64,
}

impl XdrClient {
    pub fn new(config: Config, debug_enabled: bool) -> Self {
        Self {
            client: Client::new(),
            config,
            debug_enabled,
            last_successful_poll: Arc::new(std::sync::Mutex::new(None)),
            consecutive_errors: Arc::new(AtomicU64::new(0)),

            // Sync cursor
            sync_cursor: Arc::new(std::sync::Mutex::new(None)),

            // Cache configuration - 2 minutes cache duration for large paginated datasets
            cached_cases: Arc::new(std::sync::Mutex::new(None)),
            cache_timestamp: Arc::new(std::sync::Mutex::new(None)),
            cache_duration: Duration::from_secs(120),

            // Force full sync if no updates for 10 minutes
            stale_threshold_secs: 600,
        }
    }

    /// Get all cases - uses cache or fetches fresh data
    pub async fn get_cases(&self) -> Result<Vec<Case>> {
        // Check cache first to prevent unnecessary API calls
        if let Ok(cache_guard) = self.cached_cases.lock() {
            if let Some(ref cached) = *cache_guard {
                if let Ok(timestamp_guard) = self.cache_timestamp.lock() {
                    if let Some(cache_time) = *timestamp_guard {
                        if cache_time.elapsed() < self.cache_duration {
                            if self.debug_enabled {
                                self.safe_debug_log(format!(
                                    "[CACHE] HIT - Returning {} cached cases (age: {:?})",
                                    cached.len(),
                                    cache_time.elapsed()
                                ));
                            }
                            return Ok(cached.clone());
                        }
                    }
                }
            }
        }

        if self.debug_enabled {
            self.safe_debug_log("[SYNC] Cache miss or expired - fetching fresh data".to_string());
        }

        // Fetch all cases
        let cases = self.get_all_cases_paginated().await?;

        // Update cache
        if let Ok(mut cache_guard) = self.cached_cases.lock() {
            *cache_guard = Some(cases.clone());
        }
        if let Ok(mut timestamp_guard) = self.cache_timestamp.lock() {
            *timestamp_guard = Some(Instant::now());
        }

        // Update sync cursor with latest modification time
        if let Some(max_mod_time) = cases.iter().filter_map(|c| c.modification_time_raw).max() {
            if let Ok(mut cursor_guard) = self.sync_cursor.lock() {
                *cursor_guard = Some(max_mod_time);
            }
            if self.debug_enabled {
                self.safe_debug_log(format!(
                    "[SYNC] Updated cursor to modification_time: {max_mod_time}"
                ));
            }
        }

        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[CACHE] UPDATED - Stored {} cases in cache",
                cases.len()
            ));
        }

        Ok(cases)
    }

    /// Fetch all cases using proper pagination
    async fn get_all_cases_paginated(&self) -> Result<Vec<Case>> {
        let url = format!(
            "{}/public_api/v1/case/search",
            self.config.tenant_url
        );

        let mut all_cases = Vec::new();
        let mut search_from: u32 = 0;
        let page_size: u32 = 100;
        let mut dedupe_set = HashSet::new();

        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[API] Starting paginated case fetch\n  URL: {url}\n  Page Size: {page_size}"
            ));
        }

        loop {
            let search_to = search_from + page_size;

            // Create typed request payload
            let request_data = CaseSearchRequestData::full_fetch(search_from, search_to);
            let request_body = GetCasesRequest { request_data };

            if self.debug_enabled {
                self.safe_debug_log(format!(
                    "[API] Request page {}\n  Range: {} - {}\n  Body: {}",
                    (search_from / page_size) + 1,
                    search_from,
                    search_to,
                    serde_json::to_string_pretty(&request_body)
                        .unwrap_or_else(|_| "Failed to serialise".to_string())
                ));
            }

            let response = self
                .client
                .post(&url)
                .header("x-xdr-auth-id", &self.config.api_key_id)
                .header("Authorization", &self.config.api_key_secret)
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(30))
                .json(&request_body)
                .send()
                .await
                .map_err(|e| {
                    self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                    anyhow!(
                        "Network error during pagination: {}",
                        sanitise_error_message(&e.to_string())
                    )
                })?;

            let status = response.status();

            // Handle rate limiting
            if status == 429 {
                self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                if self.debug_enabled {
                    self.safe_debug_log("[API] Rate limit (429) - will retry with backoff".to_string());
                }
                return Err(anyhow!(
                    "Rate limit exceeded during pagination - will retry with backoff"
                ));
            }

            if !status.is_success() {
                self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "No response body".to_string());
                if self.debug_enabled {
                    self.safe_debug_log(format!(
                        "[API] Error response\n  Status: {status}\n  Body: {error_body}"
                    ));
                }
                return Err(anyhow!(
                    "API request failed with status: {status} - {error_body}"
                ));
            }

            let body = response.text().await.map_err(|e| {
                self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                anyhow!("Failed to read response body: {e}")
            })?;

            let response: GetCasesResponse = serde_json::from_str(&body).map_err(|e| {
                self.consecutive_errors.fetch_add(1, Ordering::Relaxed);
                if self.debug_enabled {
                    let truncated_body = &body[..body.len().min(500)];
                    self.safe_debug_log(format!(
                        "[API] Parse error\n  Error: {e}\n  Body: {truncated_body}"
                    ));
                }
                anyhow!("Invalid response format: {e}")
            })?;

            let total_count = response.reply.total_count;
            let page_cases = response.reply.data;

            if self.debug_enabled {
                self.safe_debug_log(format!(
                    "[API] Page {} received\n  Cases: {}\n  Total count: {}\n  Collected so far: {}",
                    (search_from / page_size) + 1,
                    page_cases.len(),
                    total_count,
                    all_cases.len()
                ));
            }

            // Convert and deduplicate cases
            for api_case in page_cases {
                let case_id = api_case.case_id.to_string();
                if dedupe_set.insert(case_id) {
                    let case = self.convert_api_case(api_case);
                    all_cases.push(case);
                }
            }

            // Check if we've fetched all available cases
            if search_to >= total_count {
                if self.debug_enabled {
                    self.safe_debug_log(format!(
                        "[API] Pagination complete\n  Unique cases: {}\n  Total count: {}",
                        all_cases.len(),
                        total_count
                    ));
                }
                break;
            }

            search_from += page_size;
        }

        // Success - reset error counter
        self.consecutive_errors.store(0, Ordering::Relaxed);

        if let Ok(mut last_success) = self.last_successful_poll.lock() {
            *last_success = Some(Instant::now());
        }

        Ok(all_cases)
    }

    /// Get adaptive poll interval based on error state
    pub fn get_adaptive_poll_interval(&self) -> Duration {
        let error_count = self.consecutive_errors.load(Ordering::Relaxed);

        // Base interval matches cache duration
        let base_interval = 120000; // 2 minutes

        let interval_ms = if error_count == 0 {
            if let Ok(last_poll) = self.last_successful_poll.lock() {
                if let Some(last_time) = *last_poll {
                    if last_time.elapsed() < Duration::from_secs(600) {
                        base_interval
                    } else {
                        base_interval * 2
                    }
                } else {
                    base_interval
                }
            } else {
                base_interval
            }
        } else {
            // Exponential backoff for errors
            let backoff_multiplier = 1 << std::cmp::min(error_count, 6);
            let max_interval = 600000; // 10 minutes maximum
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

    /// Clear cache to force fresh data fetch
    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        if let Ok(mut cache_guard) = self.cached_cases.lock() {
            *cache_guard = None;
        }
        if let Ok(mut timestamp_guard) = self.cache_timestamp.lock() {
            *timestamp_guard = None;
        }
        if let Ok(mut cursor_guard) = self.sync_cursor.lock() {
            *cursor_guard = None;
        }
        if self.debug_enabled {
            self.safe_debug_log("[CACHE] Cleared - forcing fresh data fetch".to_string());
        }
    }

    /// Convert API case to domain Case structure
    fn convert_api_case(&self, api_case: ApiCase) -> Case {
        let creation_time = api_case.creation_time
            .and_then(|ts| DateTime::from_timestamp(ts as i64 / 1000, 0))
            .unwrap_or_else(Utc::now);

        let modification_time_raw = api_case.modification_time;

        let last_updated = modification_time_raw
            .and_then(|ts| DateTime::from_timestamp(ts as i64 / 1000, 0));

        // Extract description
        let description = api_case.description.clone().unwrap_or_default();

        // Get issue count
        let issue_count = api_case.issue_count.unwrap_or_else(|| {
            api_case.issue_ids.as_ref().map(|ids| ids.len() as u32).unwrap_or(1)
        });

        // Parse MITRE tactics from "TA0002 - Execution" format to just "Execution"
        let mitre_tactics = api_case.mitre_tactics_ids_and_names
            .unwrap_or_default()
            .iter()
            .map(|s| {
                // Extract name after " - " if present
                if let Some(pos) = s.find(" - ") {
                    s[pos + 3..].to_string()
                } else {
                    s.clone()
                }
            })
            .collect();

        // Parse MITRE techniques from "T1552.007 - Unsecured Credentials: Container API" format
        let mitre_techniques = api_case.mitre_techniques_ids_and_names
            .unwrap_or_default()
            .iter()
            .map(|s| {
                // Extract name after " - " if present
                if let Some(pos) = s.find(" - ") {
                    s[pos + 3..].to_string()
                } else {
                    s.clone()
                }
            })
            .collect();

        // Get hosts
        let hosts = api_case.hosts.clone().unwrap_or_default();

        // Get users
        let users = api_case.users.clone().unwrap_or_default();

        // Get status - map status_progress field
        let status = api_case.status_progress.clone().unwrap_or_else(|| "Unknown".to_string());

        // Get severity
        let severity = api_case.severity.clone().unwrap_or_else(|| "unknown".to_string());

        // Get case domain
        let case_domain = api_case.case_domain.clone();

        // Get XDR URL for quick access
        let xdr_url = api_case.xdr_url.clone();

        // Get tags
        let tags = api_case.tags.clone().unwrap_or_default();

        // Create empty issues list (populated on drill-down)
        let issues: Vec<IssueDetail> = Vec::new();

        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[CONVERT] Case {} -> domain: {:?}, status: {}, severity: {}, issues: {}",
                api_case.case_id,
                case_domain,
                status,
                severity,
                issue_count
            ));
        }

        // Preserve issue_ids for drill-down fetching
        let issue_ids = api_case.issue_ids.clone();

        Case {
            id: api_case.case_id.to_string(),
            status,
            severity,
            description,
            creation_time,
            last_updated,
            modification_time_raw,
            issue_count,
            issue_ids,
            issues,
            mitre_tactics,
            mitre_techniques,
            case_domain,
            hosts,
            users,
            xdr_url,
            tags,
        }
    }

    /// Get issues for specific case by issue IDs (on-demand fetch for drill-down)
    /// Uses issue_ids from the Cases API response to filter by 'id' field
    pub async fn get_case_issues(&self, case_id: &str, issue_ids: Option<&[i64]>) -> Result<Vec<IssueDetail>> {
        let url = format!(
            "{}/public_api/v1/issue/search",
            self.config.tenant_url
        );

        // Check if we have issue_ids to filter by
        let issue_ids_slice = match issue_ids {
            Some(ids) if !ids.is_empty() => ids,
            _ => {
                if self.debug_enabled {
                    self.safe_debug_log(format!(
                        "[API] No issue_ids available for case {case_id} - cannot fetch issue details"
                    ));
                }
                return Ok(Vec::new());
            }
        };

        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[API] Fetching {} issues for case {case_id}\n  URL: {url}\n  Issue IDs: {:?}",
                issue_ids_slice.len(),
                issue_ids_slice
            ));
        }

        // Create typed request payload using issue IDs filter
        let request_data = IssueSearchRequestData::by_issue_ids(issue_ids_slice, 0, 100);
        let request_body = GetIssuesRequest { request_data };

        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[API] Issue search request\n  Body: {}",
                serde_json::to_string_pretty(&request_body)
                    .unwrap_or_else(|_| "Failed to serialise".to_string())
            ));
        }

        let response = self
            .client
            .post(&url)
            .header("x-xdr-auth-id", &self.config.api_key_id)
            .header("Authorization", &self.config.api_key_secret)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(15))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "Network error fetching issues: {}",
                    sanitise_error_message(&e.to_string())
                )
            })?;

        let status = response.status();

        if !status.is_success() {
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "No response body".to_string());
            if self.debug_enabled {
                self.safe_debug_log(format!(
                    "[API] Issue search error\n  Status: {status}\n  Body: {error_body}"
                ));
            }
            return Err(anyhow!(
                "Issue search failed with status: {status} - {error_body}"
            ));
        }

        let body = response.text().await.map_err(|e| {
            anyhow!("Failed to read issue response body: {e}")
        })?;

        let response: GetIssuesResponse = serde_json::from_str(&body).map_err(|e| {
            if self.debug_enabled {
                let truncated_body = &body[..body.len().min(500)];
                self.safe_debug_log(format!(
                    "[API] Issue parse error\n  Error: {e}\n  Body: {truncated_body}"
                ));
            }
            anyhow!("Invalid issue response format: {e}")
        })?;

        let api_issues = response.reply.data;
        let total_count = response.reply.total_count.unwrap_or(api_issues.len() as u32);

        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[API] Issues received for case {case_id}\n  Count: {}\n  Total: {}",
                api_issues.len(),
                total_count
            ));
        }

        // Convert API issues to domain IssueDetail structures
        let issues: Vec<IssueDetail> = api_issues
            .into_iter()
            .map(|api_issue| self.convert_api_issue(api_issue))
            .collect();

        Ok(issues)
    }

    /// Convert API issue to domain IssueDetail structure
    fn convert_api_issue(&self, api_issue: ApiIssue) -> IssueDetail {
        let name = api_issue.name.unwrap_or_else(|| "Unknown Issue".to_string());
        let severity = api_issue.severity.unwrap_or_else(|| "unknown".to_string());
        let category = api_issue.category.unwrap_or_else(|| "Unknown".to_string());
        
        if self.debug_enabled {
            self.safe_debug_log(format!(
                "[CONVERT] Issue -> name: {}, severity: {}, category: {}, assets: {:?}",
                name, severity, category, api_issue.asset_names
            ));
        }
        
        IssueDetail {
            name,
            severity,
            category,
            domain: api_issue.domain,
            description: api_issue.description,
            remediation: api_issue.remediation,
            asset_names: api_issue.asset_names.unwrap_or_default(),
            detection_method: api_issue.detection_method,
            tags: api_issue.tags.unwrap_or_default(),
        }
    }

    /// Safe debug logging with file output
    fn safe_debug_log(&self, message: String) {
        let timeout_duration = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();

        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("debug_output.log")
        {
            if start.elapsed() < timeout_duration {
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                let _ = writeln!(file, "[{timestamp}] {message}");
                let _ = file.flush();
            }
        }
    }
}


// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

/// Sanitise error messages to remove sensitive information
fn sanitise_error_message(error: &str) -> String {
    let mut sanitised = error.to_string();

    // Remove API keys and tokens
    if let Some(start) = sanitised.find("Authorization:") {
        if let Some(end) = sanitised[start..].find('\n') {
            sanitised.replace_range(start..start + end, "Authorization: [REDACTED]");
        }
    }

    // Remove URLs with credentials
    let patterns = ["api_key=", "token=", "secret="];
    for pattern in patterns {
        while let Some(start) = sanitised.find(pattern) {
            if let Some(end) = sanitised[start..].find(['&', ' ', '\n']) {
                sanitised.replace_range(start..start + end, &format!("{pattern}[REDACTED]"));
            } else {
                sanitised.replace_range(start.., &format!("{pattern}[REDACTED]"));
                break;
            }
        }
    }

    sanitised
}
