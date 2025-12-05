// XDRTop Types Module
// Strongly-typed enums and structs for Cortex XDR Cases and Issues API interactions
// Following British English conventions throughout
// Version 2.0.1 - Complete terminology migration to Cases/Issues

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

// ----------------------------------------------------------------------------
// Severity Enum - Type-safe case severity levels
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Severity {
    /// Returns numeric priority for sorting (higher = more severe)
    pub fn priority(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
            Severity::Unknown => 0,
        }
    }

    /// Parse severity from string (case-insensitive)
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            "info" | "informational" => Severity::Info,
            _ => Severity::Unknown,
        }
    }

    /// Returns all known severity levels for iteration
    pub fn all() -> &'static [Severity] {
        &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
            Severity::Unknown => write!(f, "Unknown"),
        }
    }
}


// ----------------------------------------------------------------------------
// Case Status Enum - Type-safe case status values (from status_progress field)
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CaseStatus {
    New,
    #[serde(rename = "Under Investigation")]
    UnderInvestigation,
    Resolved,
    #[serde(rename = "Resolved - Threat Handled")]
    ResolvedThreatHandled,
    #[serde(rename = "Resolved - Known Issue")]
    ResolvedKnownIssue,
    #[serde(rename = "Resolved - Duplicate")]
    ResolvedDuplicate,
    #[serde(rename = "Resolved - False Positive")]
    ResolvedFalsePositive,
    #[serde(rename = "Resolved - True Positive")]
    ResolvedTruePositive,
    #[serde(rename = "Resolved - Security Testing")]
    ResolvedSecurityTesting,
    #[serde(rename = "Resolved - Other")]
    ResolvedOther,
    #[default]
    #[serde(other)]
    Other,
}

impl CaseStatus {
    /// Parse status from string (case-insensitive, handles various formats)
    pub fn from_str_loose(s: &str) -> Self {
        let normalised = s.to_lowercase().replace([' ', '-'], "_");
        match normalised.as_str() {
            "new" => CaseStatus::New,
            "under_investigation" => CaseStatus::UnderInvestigation,
            "resolved" => CaseStatus::Resolved,
            "resolved_threat_handled" | "resolved___threat_handled" => CaseStatus::ResolvedThreatHandled,
            "resolved_known_issue" | "resolved___known_issue" => CaseStatus::ResolvedKnownIssue,
            "resolved_duplicate" | "resolved___duplicate" => CaseStatus::ResolvedDuplicate,
            "resolved_false_positive" | "resolved___false_positive" => CaseStatus::ResolvedFalsePositive,
            "resolved_true_positive" | "resolved___true_positive" => CaseStatus::ResolvedTruePositive,
            "resolved_security_testing" | "resolved___security_testing" => CaseStatus::ResolvedSecurityTesting,
            "resolved_other" | "resolved___other" => CaseStatus::ResolvedOther,
            _ => CaseStatus::Other,
        }
    }

    /// Check if this is a resolved status
    pub fn is_resolved(&self) -> bool {
        matches!(
            self,
            CaseStatus::Resolved
                | CaseStatus::ResolvedThreatHandled
                | CaseStatus::ResolvedKnownIssue
                | CaseStatus::ResolvedDuplicate
                | CaseStatus::ResolvedFalsePositive
                | CaseStatus::ResolvedTruePositive
                | CaseStatus::ResolvedSecurityTesting
                | CaseStatus::ResolvedOther
        )
    }
}

impl fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaseStatus::New => write!(f, "New"),
            CaseStatus::UnderInvestigation => write!(f, "Under Investigation"),
            CaseStatus::Resolved => write!(f, "Resolved"),
            CaseStatus::ResolvedThreatHandled => write!(f, "Resolved - Threat Handled"),
            CaseStatus::ResolvedKnownIssue => write!(f, "Resolved - Known Issue"),
            CaseStatus::ResolvedDuplicate => write!(f, "Resolved - Duplicate"),
            CaseStatus::ResolvedFalsePositive => write!(f, "Resolved - False Positive"),
            CaseStatus::ResolvedTruePositive => write!(f, "Resolved - True Positive"),
            CaseStatus::ResolvedSecurityTesting => write!(f, "Resolved - Security Testing"),
            CaseStatus::ResolvedOther => write!(f, "Resolved - Other"),
            CaseStatus::Other => write!(f, "Other"),
        }
    }
}


// ----------------------------------------------------------------------------
// API Request Types - Strongly-typed request structures for case/search
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct GetCasesRequest {
    pub request_data: CaseSearchRequestData,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseSearchRequestData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<CaseFilter>,
    pub search_from: u32,
    pub search_to: u32,
    pub sort: CaseSortConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseFilter {
    pub field: CaseFilterField,
    pub operator: CaseFilterOperator,
    pub value: serde_json::Value,
}

/// Allowed filter fields for case/search endpoint
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseFilterField {
    CaseId,
    CaseDomain,
    Severity,
    CreationTime,
    StatusProgress,
}

/// Allowed filter operators for case/search endpoint
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseFilterOperator {
    In,
    Gte,
    Lte,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseSortConfig {
    pub field: CaseSortField,
    pub keyword: SortDirection,
}

/// Allowed sort fields for case/search endpoint
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseSortField {
    CaseId,
    Severity,
    CreationTime,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    Desc,
}

impl Default for CaseSortConfig {
    fn default() -> Self {
        CaseSortConfig {
            field: CaseSortField::CreationTime,
            keyword: SortDirection::Desc,
        }
    }
}

impl CaseSearchRequestData {
    /// Create request for full dataset fetch (no filters)
    pub fn full_fetch(search_from: u32, search_to: u32) -> Self {
        CaseSearchRequestData {
            filters: Vec::new(),
            search_from,
            search_to,
            sort: CaseSortConfig::default(),
        }
    }

    /// Create request for fetching cases by creation time range
    pub fn since_creation_time(creation_time: u64, search_from: u32, search_to: u32) -> Self {
        CaseSearchRequestData {
            filters: vec![CaseFilter {
                field: CaseFilterField::CreationTime,
                operator: CaseFilterOperator::Gte,
                value: serde_json::json!(creation_time),
            }],
            search_from,
            search_to,
            sort: CaseSortConfig::default(),
        }
    }
}


// ----------------------------------------------------------------------------
// API Response Types - Strongly-typed response structures for case/search
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GetCasesResponse {
    pub reply: CasesReply,
}

#[derive(Debug, Deserialize)]
pub struct CasesReply {
    #[serde(rename = "DATA")]
    pub data: Vec<ApiCase>,
    #[serde(rename = "TOTAL_COUNT")]
    pub total_count: u32,
    #[serde(rename = "FILTER_COUNT", default)]
    pub filter_count: Option<u32>,
}

/// API Case structure matching the actual case/search response
#[derive(Debug, Deserialize)]
pub struct ApiCase {
    pub case_id: i64,
    
    #[serde(default)]
    pub case_name: Option<String>,
    
    #[serde(default)]
    pub status_progress: Option<String>,
    
    #[serde(default)]
    pub severity: Option<String>,
    
    #[serde(default)]
    pub description: Option<String>,
    
    #[serde(default)]
    pub creation_time: Option<u64>,
    
    #[serde(default)]
    pub modification_time: Option<u64>,
    
    #[serde(default)]
    pub case_domain: Option<String>,
    
    #[serde(default)]
    pub issue_count: Option<u32>,
    
    #[serde(default)]
    pub issue_ids: Option<Vec<i64>>,
    
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
    
    #[serde(default)]
    pub users: Option<Vec<String>>,
    
    #[serde(default)]
    pub mitre_tactics_ids_and_names: Option<Vec<String>>,
    
    #[serde(default)]
    pub mitre_techniques_ids_and_names: Option<Vec<String>>,
    
    #[serde(default)]
    pub xdr_url: Option<String>,
    
    #[serde(default)]
    pub resolve_reason: Option<String>,
    
    #[serde(default)]
    pub resolve_comment: Option<String>,
    
    #[serde(default)]
    pub assigned_user_mail: Option<String>,
    
    #[serde(default)]
    pub assigned_user_pretty_name: Option<String>,
    
    #[serde(default)]
    pub aggregated_score: Option<i32>,
    
    #[serde(default)]
    pub starred: Option<bool>,
    
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    
    #[serde(default)]
    pub issue_categories: Option<Vec<String>>,
    
    #[serde(default)]
    pub low_severity_issue_count: Option<u32>,
    
    #[serde(default)]
    pub med_severity_issue_count: Option<u32>,
    
    #[serde(default)]
    pub high_severity_issue_count: Option<u32>,
    
    #[serde(default)]
    pub critical_severity_issue_count: Option<u32>,
    
    #[serde(default)]
    pub host_count: Option<u32>,
    
    #[serde(default)]
    pub user_count: Option<u32>,
}


// ----------------------------------------------------------------------------
// Issue Search API Request Types - For /public_api/v1/issue/search
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct GetIssuesRequest {
    pub request_data: IssueSearchRequestData,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueSearchRequestData {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<IssueFilter>,
    pub search_from: u32,
    pub search_to: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueFilter {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

impl IssueSearchRequestData {
    /// Create request for fetching issues by case_id
    pub fn by_case_id(case_id: i64, search_from: u32, search_to: u32) -> Self {
        IssueSearchRequestData {
            filters: vec![IssueFilter {
                field: "case_id".to_string(),
                operator: "eq".to_string(),
                value: serde_json::json!(case_id),
            }],
            search_from,
            search_to,
        }
    }
}


// ----------------------------------------------------------------------------
// Issue Search API Response Types - For /public_api/v1/issue/search
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GetIssuesResponse {
    pub reply: IssuesReply,
}

#[derive(Debug, Deserialize)]
pub struct IssuesReply {
    #[serde(rename = "DATA")]
    pub data: Vec<ApiIssue>,
    #[serde(rename = "TOTAL_COUNT", default)]
    pub total_count: Option<u32>,
}

/// API Issue structure matching the actual issue/search response
#[derive(Debug, Clone, Deserialize)]
pub struct ApiIssue {
    #[serde(default)]
    pub id: Option<i64>,
    
    #[serde(default)]
    pub external_id: Option<String>,
    
    #[serde(default)]
    pub name: Option<String>,
    
    #[serde(default)]
    pub description: Option<String>,
    
    #[serde(default)]
    pub severity: Option<String>,
    
    #[serde(default)]
    pub category: Option<String>,
    
    #[serde(default)]
    pub domain: Option<String>,
    
    #[serde(rename = "status.progress", default)]
    pub status_progress: Option<String>,
    
    #[serde(rename = "detection.method", default)]
    pub detection_method: Option<String>,
    
    #[serde(default)]
    pub remediation: Option<String>,
    
    #[serde(default)]
    pub asset_names: Option<Vec<String>>,
    
    #[serde(default)]
    pub asset_categories: Option<Vec<String>>,
    
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    
    #[serde(default)]
    pub findings: Option<Vec<String>>,
    
    #[serde(default)]
    pub observation_time: Option<u64>,
    
    #[serde(default)]
    pub last_update_timestamp: Option<u64>,
}


// ----------------------------------------------------------------------------
// Cache Types - For incremental sync tracking
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SyncCursor {
    pub last_modification_time: u64,
    pub last_sync_timestamp: std::time::Instant,
}

impl SyncCursor {
    pub fn new(modification_time: u64) -> Self {
        SyncCursor {
            last_modification_time: modification_time,
            last_sync_timestamp: std::time::Instant::now(),
        }
    }

    /// Check if cursor is stale (older than threshold)
    pub fn is_stale(&self, threshold_secs: u64) -> bool {
        self.last_sync_timestamp.elapsed().as_secs() > threshold_secs
    }
}


// ----------------------------------------------------------------------------
// Unit Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str_loose("Critical"), Severity::Critical);
        assert_eq!(Severity::from_str_loose("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_str_loose("critical"), Severity::Critical);
        assert_eq!(Severity::from_str_loose("high"), Severity::High);
        assert_eq!(Severity::from_str_loose("info"), Severity::Info);
        assert_eq!(Severity::from_str_loose("unknown_value"), Severity::Unknown);
    }

    #[test]
    fn test_severity_priority() {
        assert!(Severity::Critical.priority() > Severity::High.priority());
        assert!(Severity::High.priority() > Severity::Medium.priority());
        assert!(Severity::Medium.priority() > Severity::Low.priority());
        assert!(Severity::Low.priority() > Severity::Info.priority());
    }

    #[test]
    fn test_case_status_from_str() {
        assert_eq!(
            CaseStatus::from_str_loose("new"),
            CaseStatus::New
        );
        assert_eq!(
            CaseStatus::from_str_loose("under_investigation"),
            CaseStatus::UnderInvestigation
        );
        assert_eq!(
            CaseStatus::from_str_loose("resolved - false positive"),
            CaseStatus::ResolvedFalsePositive
        );
        assert_eq!(
            CaseStatus::from_str_loose("Resolved - Security Testing"),
            CaseStatus::ResolvedSecurityTesting
        );
    }

    #[test]
    fn test_case_status_is_resolved() {
        assert!(!CaseStatus::New.is_resolved());
        assert!(!CaseStatus::UnderInvestigation.is_resolved());
        assert!(CaseStatus::Resolved.is_resolved());
        assert!(CaseStatus::ResolvedFalsePositive.is_resolved());
        assert!(CaseStatus::ResolvedSecurityTesting.is_resolved());
    }

    #[test]
    fn test_case_search_request_data() {
        let request = CaseSearchRequestData::full_fetch(0, 100);
        assert!(request.filters.is_empty());
        assert_eq!(request.search_from, 0);
        assert_eq!(request.search_to, 100);
    }
}
