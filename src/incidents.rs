use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Alert {
    pub name: String,
    pub severity: String,
    pub category: String,
    pub source: Option<String>,
    pub host_name: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: String,
    pub status: String,
    pub severity: String,
    pub description: String,
    pub creation_time: DateTime<Utc>,
    pub last_updated: Option<DateTime<Utc>>,

    pub alerts: Vec<Alert>,
}

impl Incident {
    pub fn severity_priority(&self) -> u8 {
        match self.severity.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        }
    }

    pub fn truncated_description(&self, max_len: usize) -> String {
        if self.description.len() <= max_len {
            self.description.clone()
        } else {
            format!("{}...", &self.description[..max_len.saturating_sub(3)])
        }
    }
}

pub struct IncidentStore {
    incidents: HashMap<String, Incident>,
    sorted_incidents: Vec<Incident>,
}

impl IncidentStore {
    pub fn new() -> Self {
        Self {
            incidents: HashMap::new(),
            sorted_incidents: Vec::new(),
        }
    }

    pub fn update(&mut self, new_incidents: Vec<Incident>) {
        // Clear existing incidents and update with new ones
        self.incidents.clear();

        for incident in new_incidents {
            self.incidents.insert(incident.id.clone(), incident);
        }

        // Sort incidents by severity (highest first) then by creation time (newest first)
        self.sorted_incidents = self.incidents.values().cloned().collect();
        self.sorted_incidents.sort_by(|a, b| {
            match b.severity_priority().cmp(&a.severity_priority()) {
                std::cmp::Ordering::Equal => b.creation_time.cmp(&a.creation_time),
                other => other,
            }
        });
    }

    pub fn get_all(&self) -> &[Incident] {
        &self.sorted_incidents
    }
}
