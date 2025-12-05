// XDRTop Cases Module
// Core data structures for case and issue management
// Version 2.0.1 - Complete terminology migration to Cases/Issues
// Following British English conventions throughout

use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::types::Severity;

// ----------------------------------------------------------------------------
// IssueDetail Structure - Detailed issue information for drill-down view
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct IssueDetail {
    pub name: String,
    pub severity: String,
    pub category: String,
    #[allow(dead_code)]
    pub domain: Option<String>,
    pub description: Option<String>,
    pub remediation: Option<String>,
    pub asset_names: Vec<String>,
    pub detection_method: Option<String>,
    #[allow(dead_code)]
    pub tags: Vec<String>,
}

// ----------------------------------------------------------------------------
// Case Structure - Represents a security case from the Cases API
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Case {
    pub id: String,
    pub status: String,
    pub severity: String,
    pub description: String,
    pub creation_time: DateTime<Utc>,
    pub last_updated: Option<DateTime<Utc>>,
    pub modification_time_raw: Option<u64>,
    pub issue_count: u32,
    pub issues: Vec<IssueDetail>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub case_domain: Option<String>,
    #[allow(dead_code)]
    pub hosts: Vec<String>,
    #[allow(dead_code)]
    pub users: Vec<String>,
    #[allow(dead_code)]
    pub xdr_url: Option<String>,
    #[allow(dead_code)]
    pub tags: Vec<String>,
}

impl Case {
    /// Returns typed severity enum for type-safe comparisons
    pub fn severity_typed(&self) -> Severity {
        Severity::from_str_loose(&self.severity)
    }

    /// Returns numeric priority for sorting (higher = more severe)
    pub fn severity_priority(&self) -> u8 {
        self.severity_typed().priority()
    }

    /// Truncate description for display with ellipsis
    /// Uses character-boundary-aware truncation to handle multi-byte UTF-8 characters
    pub fn truncated_description(&self, max_len: usize) -> String {
        if self.description.chars().count() <= max_len {
            self.description.clone()
        } else {
            // Find the byte index of the character at position (max_len - 3)
            // to leave room for the ellipsis
            let char_limit = max_len.saturating_sub(3);
            let truncate_at = self
                .description
                .char_indices()
                .nth(char_limit)
                .map(|(idx, _)| idx)
                .unwrap_or(self.description.len());
            format!("{}...", &self.description[..truncate_at])
        }
    }

    /// Returns the raw modification time for sync cursor
    #[allow(dead_code)]
    pub fn get_modification_time(&self) -> Option<u64> {
        self.modification_time_raw
    }

    /// Get formatted hosts list for display
    #[allow(dead_code)]
    pub fn hosts_display(&self) -> String {
        if self.hosts.is_empty() {
            "-".to_string()
        } else {
            self.hosts.join(", ")
        }
    }

    /// Get formatted users list for display
    #[allow(dead_code)]
    pub fn users_display(&self) -> String {
        if self.users.is_empty() {
            "-".to_string()
        } else {
            self.users.join(", ")
        }
    }
}

// ----------------------------------------------------------------------------
// CaseStore - Manages case collection with optimised operations
// ----------------------------------------------------------------------------

pub struct CaseStore {
    cases: HashMap<String, Case>,
    sorted_cases: Vec<Case>,
    last_max_modification_time: Option<u64>,
    observed_domains: Vec<String>,
}

impl CaseStore {
    pub fn new() -> Self {
        Self {
            cases: HashMap::new(),
            sorted_cases: Vec::new(),
            last_max_modification_time: None,
            observed_domains: Vec::new(),
        }
    }

    /// Update store with new cases (full replacement)
    pub fn update(&mut self, new_cases: Vec<Case>) {
        let new_case_count = new_cases.len();

        // Track maximum modification time for sync cursor
        let mut max_mod_time: Option<u64> = self.last_max_modification_time;
        for case in &new_cases {
            if let Some(mod_time) = case.modification_time_raw {
                max_mod_time = Some(max_mod_time.map_or(mod_time, |current| current.max(mod_time)));
            }
        }
        self.last_max_modification_time = max_mod_time;

        // Check if we can skip expensive operations
        if new_case_count == self.cases.len() {
            let mut same_cases = true;
            for case in &new_cases {
                if !self.cases.contains_key(&case.id) {
                    same_cases = false;
                    break;
                }
            }
            if same_cases {
                return;
            }
        }

        // Clear and update with optimised capacity allocation
        self.cases.clear();
        self.cases.reserve(new_case_count);

        // Track observed domains
        let mut domain_set: std::collections::HashSet<String> = std::collections::HashSet::new();

        for case in new_cases {
            if let Some(ref domain) = case.case_domain {
                if !domain.is_empty() {
                    domain_set.insert(domain.clone());
                }
            }
            self.cases.insert(case.id.clone(), case);
        }

        // Update observed domains list (sorted for consistent display)
        self.observed_domains = domain_set.into_iter().collect();
        self.observed_domains.sort();

        // Pre-allocate sorted vector to avoid reallocations
        self.sorted_cases.clear();
        self.sorted_cases.reserve(self.cases.len());
        self.sorted_cases.extend(self.cases.values().cloned());

        // Sort by severity (highest first) then by creation time (newest first)
        self.sorted_cases.sort_unstable_by(|a, b| {
            match b.severity_priority().cmp(&a.severity_priority()) {
                std::cmp::Ordering::Equal => b.creation_time.cmp(&a.creation_time),
                other => other,
            }
        });
    }

    /// Merge incremental updates with existing data
    #[allow(dead_code)]
    pub fn merge_incremental(&mut self, updated_cases: Vec<Case>) {
        if updated_cases.is_empty() {
            return;
        }

        // Track maximum modification time
        let mut max_mod_time: Option<u64> = self.last_max_modification_time;

        // Track domains from updates
        let mut domain_set: std::collections::HashSet<String> =
            self.observed_domains.iter().cloned().collect();

        for case in updated_cases {
            if let Some(mod_time) = case.modification_time_raw {
                max_mod_time = Some(max_mod_time.map_or(mod_time, |current| current.max(mod_time)));
            }
            if let Some(ref domain) = case.case_domain {
                if !domain.is_empty() {
                    domain_set.insert(domain.clone());
                }
            }
            self.cases.insert(case.id.clone(), case);
        }

        self.last_max_modification_time = max_mod_time;
        self.observed_domains = domain_set.into_iter().collect();
        self.observed_domains.sort();

        // Re-sort after merge
        self.sorted_cases.clear();
        self.sorted_cases.reserve(self.cases.len());
        self.sorted_cases.extend(self.cases.values().cloned());

        self.sorted_cases.sort_unstable_by(|a, b| {
            match b.severity_priority().cmp(&a.severity_priority()) {
                std::cmp::Ordering::Equal => b.creation_time.cmp(&a.creation_time),
                other => other,
            }
        });
    }

    /// Get all cases (sorted)
    pub fn get_all(&self) -> &[Case] {
        &self.sorted_cases
    }

    /// Get the last maximum modification time for sync cursor
    #[allow(dead_code)]
    pub fn get_last_modification_time(&self) -> Option<u64> {
        self.last_max_modification_time
    }

    /// Get list of observed case domains for filtering
    #[allow(dead_code)]
    pub fn get_observed_domains(&self) -> &[String] {
        &self.observed_domains
    }

    /// Get total case count
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    /// Check if store is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }
}

impl Default for CaseStore {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------------------
// Unit Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_case(id: &str, severity: &str, domain: Option<&str>) -> Case {
        Case {
            id: id.to_string(),
            status: "New".to_string(),
            severity: severity.to_string(),
            description: "Test case".to_string(),
            creation_time: Utc::now(),
            last_updated: None,
            modification_time_raw: Some(1234567890),
            issue_count: 1,
            issues: Vec::new(),
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
            case_domain: domain.map(|s| s.to_string()),
            hosts: vec!["test-host".to_string()],
            users: vec!["test-user".to_string()],
            xdr_url: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_severity_priority() {
        let critical = create_test_case("1", "Critical", None);
        let high = create_test_case("2", "High", None);
        let medium = create_test_case("3", "Medium", None);
        let low = create_test_case("4", "Low", None);

        assert!(critical.severity_priority() > high.severity_priority());
        assert!(high.severity_priority() > medium.severity_priority());
        assert!(medium.severity_priority() > low.severity_priority());
    }

    #[test]
    fn test_case_store_domains() {
        let mut store = CaseStore::new();
        let cases = vec![
            create_test_case("1", "High", Some("Network")),
            create_test_case("2", "Medium", Some("Endpoint")),
            create_test_case("3", "Low", Some("Network")),
        ];

        store.update(cases);

        let domains = store.get_observed_domains();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"Endpoint".to_string()));
        assert!(domains.contains(&"Network".to_string()));
    }

    #[test]
    fn test_truncated_description() {
        let mut case = create_test_case("1", "High", None);
        case.description = "This is a very long description that should be truncated".to_string();

        let truncated = case.truncated_description(20);
        assert!(truncated.chars().count() <= 20);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_truncated_description_utf8() {
        // Test with multi-byte UTF-8 characters (smart quotes, em dashes, etc.)
        let mut case = create_test_case("1", "High", None);
        case.description = r#"The X-Frame-Options header is used to prevent so-called "clickjacking" attacks"#.to_string();

        // This should not panic - the bug was slicing at byte 57 which was inside the smart quote
        let truncated = case.truncated_description(60);
        assert!(truncated.chars().count() <= 60);
        assert!(truncated.ends_with("..."));

        // Test with standard ASCII string
        case.description = "Security issue detected in system files".to_string();
        let truncated = case.truncated_description(30);
        assert!(truncated.chars().count() <= 30);
    }

    #[test]
    fn test_hosts_display() {
        let mut case = create_test_case("1", "High", None);
        assert_eq!(case.hosts_display(), "test-host");

        case.hosts = vec!["host1".to_string(), "host2".to_string()];
        assert_eq!(case.hosts_display(), "host1, host2");

        case.hosts = Vec::new();
        assert_eq!(case.hosts_display(), "-");
    }

    #[test]
    fn test_users_display() {
        let mut case = create_test_case("1", "High", None);
        assert_eq!(case.users_display(), "test-user");

        case.users = vec!["user1".to_string(), "user2".to_string()];
        assert_eq!(case.users_display(), "user1, user2");

        case.users = Vec::new();
        assert_eq!(case.users_display(), "-");
    }
}
