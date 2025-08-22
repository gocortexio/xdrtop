use chrono::{DateTime, Utc};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use std::collections::{HashMap, VecDeque};

use crate::incidents::{Incident, Alert};

pub struct App {
    pub incidents: Vec<Incident>,
    pub filtered_incidents: Vec<Incident>,
    pub table_state: TableState,
    pub status_message: String,
    pub is_error: bool,
    pub last_update: chrono::DateTime<chrono::Utc>,
    pub drill_down_mode: bool,
    pub selected_incident: Option<Incident>,
    pub severity_filter: Option<String>,
    pub status_filter: Option<String>,
    pub api_calls: VecDeque<DateTime<Utc>>,
    pub next_poll_time: Option<DateTime<Utc>>,
    pub tenant_url: Option<String>,
    pub loading_large_dataset: bool,
    pub last_key_time: std::time::Instant,
}

impl App {
    pub fn new() -> Self {
        Self {
            incidents: Vec::new(),
            filtered_incidents: Vec::new(),
            table_state: TableState::default(),
            status_message: "".to_string(),
            is_error: false,
            last_update: chrono::Utc::now(),
            drill_down_mode: false,
            selected_incident: None,
            severity_filter: None,
            status_filter: None,
            api_calls: VecDeque::new(),
            next_poll_time: None,
            tenant_url: None,
            loading_large_dataset: false,
            last_key_time: std::time::Instant::now(),
        }
    }

    pub fn set_incidents(&mut self, incidents: &[Incident]) {
        // Handle large datasets (>500 cases) with optimised loading
        if incidents.len() > 500 {
            self.loading_large_dataset = true;
            self.status_message = format!("Loading {} cases...", incidents.len());
        }
        
        // Skip redundant operations if incidents haven't changed
        if incidents.len() == self.incidents.len() && 
           incidents.iter().zip(&self.incidents).all(|(a, b)| a.id == b.id) {
            self.loading_large_dataset = false;
            return;
        }
        
        // Pre-allocate vectors for large datasets to avoid reallocations
        if incidents.len() > self.incidents.capacity() {
            self.incidents.reserve(incidents.len());
        }
        
        // Memory optimization: avoid unnecessary copying by using clone_from when possible
        if self.incidents.len() == incidents.len() {
            // Reuse existing capacity and update in-place
            self.incidents.clone_from_slice(incidents);
        } else {
            // Only allocate new vector when size changes
            self.incidents = incidents.to_vec();
        }
        self.apply_filters();
        self.last_update = chrono::Utc::now();
        self.loading_large_dataset = false;

        // Reset selection if we have fewer incidents than before
        let incident_count = self.filtered_incidents.len();
        if let Some(selected) = self.table_state.selected() {
            if selected >= incident_count && incident_count > 0 {
                self.table_state.select(Some(incident_count - 1));
            }
        } else if incident_count > 0 && !self.drill_down_mode {
            // Only auto-select on first load when we have no selection and not in drill-down mode
            // Don't auto-select on Windows to prevent auto-entering case details
            #[cfg(not(target_os = "windows"))]
            self.table_state.select(Some(0));
        }
    }

    fn apply_filters(&mut self) {
        // Memory optimization: avoid unnecessary cloning and allocations
        if self.severity_filter.is_none() && self.status_filter.is_none() {
            // No filters active - avoid cloning when possible
            if self.filtered_incidents.len() != self.incidents.len() {
                self.filtered_incidents.clone_from(&self.incidents);
            }
            return;
        }
        
        // Clear and pre-allocate with estimated capacity to avoid reallocations
        self.filtered_incidents.clear();
        let estimated_capacity = self.incidents.len() / 2; // Conservative estimate
        if self.filtered_incidents.capacity() < estimated_capacity {
            self.filtered_incidents.reserve(estimated_capacity);
        }
        
        for incident in &self.incidents {
            let mut include = true;
            
            if let Some(ref severity_filter) = self.severity_filter {
                if !incident.severity.eq_ignore_ascii_case(severity_filter) {
                    include = false;
                }
            }
            
            if include {
                if let Some(ref status_filter) = self.status_filter {
                    if !incident.status.eq_ignore_ascii_case(status_filter) {
                        include = false;
                    }
                }
            }
            
            if include {
                self.filtered_incidents.push(incident.clone());
            }
        }
    }

    pub fn toggle_severity_filter(&mut self, severity: String) {
        if self.severity_filter.as_ref() == Some(&severity) {
            self.severity_filter = None;
        } else {
            self.severity_filter = Some(severity);
        }
        self.apply_filters();
        self.table_state.select(Some(0));
    }

    pub fn clear_filters(&mut self) {
        self.severity_filter = None;
        self.status_filter = None;
        self.apply_filters();
    }

    pub fn cycle_status_filter(&mut self) {
        // Get unique statuses from actual data
        let mut unique_statuses: Vec<String> = self
            .incidents
            .iter()
            .map(|incident| incident.status.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        unique_statuses.sort();

        if unique_statuses.is_empty() {
            return;
        }

        let current_index = self
            .status_filter
            .as_ref()
            .and_then(|status| unique_statuses.iter().position(|s| s == status))
            .unwrap_or(unique_statuses.len() - 1);

        let next_index = (current_index + 1) % unique_statuses.len();
        if next_index == 0 && self.status_filter.is_some() {
            self.status_filter = None;
        } else {
            self.status_filter = Some(unique_statuses[next_index].clone());
        }
        self.apply_filters();
        self.table_state.select(Some(0));
    }

    pub fn set_status(&mut self, message: String, is_error: bool) {
        self.status_message = message;
        self.is_error = is_error;
    }
    
    pub fn get_filter_settings(&self) -> (Option<String>, Option<String>) {
        (self.severity_filter.clone(), self.status_filter.clone())
    }
    
    pub fn set_filter_settings(&mut self, severity_filter: Option<String>, status_filter: Option<String>) {
        self.severity_filter = severity_filter;
        self.status_filter = status_filter;
        self.apply_filters();
    }

    pub fn record_api_call(&mut self) {
        let now = chrono::Utc::now();
        
        // Prevent memory leak by maintaining a maximum size
        const MAX_API_CALLS: usize = 120; // 2 minutes at 1 call per second
        const CLEANUP_THRESHOLD: usize = 100;
        
        self.api_calls.push_back(now);

        // More aggressive cleanup to prevent memory growth
        if self.api_calls.len() >= MAX_API_CALLS {
            // Remove oldest entries first to maintain fixed size
            while self.api_calls.len() > CLEANUP_THRESHOLD {
                self.api_calls.pop_front();
            }
        }
        
        // Additional time-based cleanup every 5 calls to remove stale entries
        if self.api_calls.len() % 5 == 0 {
            let cutoff = now - chrono::Duration::seconds(60);
            self.api_calls.retain(|&time| time >= cutoff);
        }
    }

    pub fn set_next_poll_time(&mut self, poll_interval: std::time::Duration) {
        self.next_poll_time = Some(chrono::Utc::now() + chrono::Duration::from_std(poll_interval).unwrap_or(chrono::Duration::seconds(30)));
    }
    
    pub fn set_tenant_url(&mut self, url: String) {
        self.tenant_url = Some(url);
    }

    /// Memory optimization: periodically clean up old data to prevent memory growth
    /// Check if enough time has passed since last key event to prevent double-key issues on Windows
    pub fn should_process_key(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_key_time);
        
        // Require at least 100ms between key events to debounce (increased for Windows stability)
        if elapsed.as_millis() >= 100 {
            self.last_key_time = now;
            true
        } else {
            false
        }
    }

    pub fn cleanup_memory(&mut self) {
        // Clean old API call records
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(120);
        self.api_calls.retain(|&time| time >= cutoff);
        
        // Shrink capacity if vectors are oversized (more than 2x current size)
        if self.incidents.capacity() > self.incidents.len() * 2 && self.incidents.capacity() > 100 {
            self.incidents.shrink_to_fit();
        }
        
        if self.filtered_incidents.capacity() > self.filtered_incidents.len() * 2 && self.filtered_incidents.capacity() > 100 {
            self.filtered_incidents.shrink_to_fit();
        }
    }

    pub fn next(&mut self) {
        if self.filtered_incidents.is_empty() {
            return;
        }

        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered_incidents.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    pub fn previous(&mut self) {
        if self.filtered_incidents.is_empty() {
            return;
        }

        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_incidents.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(i));
    }





    pub fn get_severity_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        // Use filtered incidents if filters are active, otherwise use all incidents
        let incidents_to_count = if self.severity_filter.is_some() || self.status_filter.is_some() {
            &self.filtered_incidents
        } else {
            &self.incidents
        };
        
        for incident in incidents_to_count {
            *counts.entry(incident.severity.clone()).or_insert(0) += 1;
        }
        counts
    }



    pub fn enter_drill_down(&mut self) {
        // Only enter drill-down if we have incidents and a valid selection
        if self.filtered_incidents.is_empty() {
            return;
        }
        
        if let Some(selected_idx) = self.table_state.selected() {
            if selected_idx < self.filtered_incidents.len() {
                let incident = &self.filtered_incidents[selected_idx];

                self.selected_incident = Some(incident.clone());
                self.drill_down_mode = true;
            }
        }
    }

    pub fn exit_drill_down(&mut self) {
        self.drill_down_mode = false;
        self.selected_incident = None;
        
        // Ensure we have a valid selection when returning to main view
        if !self.filtered_incidents.is_empty() && self.table_state.selected().is_none() {
            self.table_state.select(Some(0));
        }
    }

    pub fn is_drill_down_mode(&self) -> bool {
        self.drill_down_mode
    }

    pub fn get_selected_incident(&self) -> Option<&Incident> {
        self.selected_incident.as_ref()
    }
    
    pub fn update_selected_incident_alerts(&mut self, alerts: Vec<Alert>) {
        if let Some(ref mut incident) = self.selected_incident {
            // Only update alerts, preserve the original alert_count from the main incidents API
            // The main incidents API has the authoritative count, individual alerts API may be incomplete
            incident.alerts = alerts;
        }
    }
    
    pub fn prepare_for_drill_down(&mut self, incident_id: &str) {
        // Find and clone the incident to prepare for drill-down mode
        if let Some(incident) = self.filtered_incidents.iter().find(|i| i.id == incident_id) {
            self.selected_incident = Some(incident.clone());
        }
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Safety check: if we're in drill-down mode but have no selected incident, exit drill-down
    if app.is_drill_down_mode() && app.get_selected_incident().is_none() {
        app.exit_drill_down();
    }

    if app.is_drill_down_mode() {
        draw_drill_down_view(f, size, app);
    } else {
        draw_main_view(f, size, app);
    }
}

fn draw_main_view(f: &mut Frame, size: Rect, app: &mut App) {
    // Main layout
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(size);

    // Header
    draw_header(f, main_chunks[0], app);

    // Main content layout
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(75), Constraint::Percentage(25)])
        .split(main_chunks[1]);

    // Incidents table
    draw_incidents_table(f, content_chunks[0], app);

    // Sidebar with stats and details
    draw_sidebar(f, content_chunks[1], app);

    // Status bar
    draw_status_bar(f, main_chunks[2], app);
}

fn draw_drill_down_view(f: &mut Frame, size: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Incident details
            Constraint::Length(3), // Status bar
        ])
        .split(size);

    // Header with drill-down indicator
    draw_drill_down_header(f, chunks[0], app);

    // Incident details
    draw_incident_details(f, chunks[1], app);

    // Status bar with navigation help
    draw_drill_down_status_bar(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Title with version number from Cargo.toml
    let title_text = format!("XDRTop - Cortex XDR Case Monitor v{}", env!("CARGO_PKG_VERSION"));
    let title = Paragraph::new(title_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, header_chunks[0]);

    // Stats summary
    let total_incidents = app.incidents.len();
    let filtered_count = app.filtered_incidents.len();
    let last_update = app.last_update.format("%H:%M:%S").to_string();

    let stats_text = if total_incidents != filtered_count {
        format!(
            "Cases: {}/{} | Updated: {}",
            filtered_count, total_incidents, last_update
        )
    } else {
        format!(
            "Total Cases: {} | Updated: {}",
            total_incidents, last_update
        )
    };

    let stats = Paragraph::new(stats_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Stats"));
    f.render_widget(stats, header_chunks[1]);
}

fn draw_incidents_table(f: &mut Frame, area: Rect, app: &mut App) {
    let header_cells = [
        "ID",
        "Severity", 
        "Status",
        "Description",
        "Issues",
        "Created",
        "Last Updated",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });

    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Disable viewport rendering to fix scrolling issues - render all rows
    let rows = app.filtered_incidents.iter().map(|incident| {
        // Use cached style functions
        let severity_style = get_severity_style(&incident.severity);
        let status_style = get_status_style(&incident.status);

        // Optimised string operations - use owned strings to avoid borrow issues
        let id_display = incident.id.chars().take(10).collect::<String>();
        let alert_count = incident.alert_count.to_string();
        let formatted_created = incident.creation_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let formatted_updated = incident.last_updated
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "".to_string());

        Row::new(vec![
            Cell::from(id_display),
            Cell::from(incident.severity.clone()).style(severity_style),
            Cell::from(incident.status.clone()).style(status_style),
            Cell::from(incident.truncated_description(85)), // Increased to use more available space
            Cell::from(alert_count),
            Cell::from(formatted_created),
            Cell::from(formatted_updated),
        ])
    });

    let widths = [
        Constraint::Length(12),     // ID (increased from 10)
        Constraint::Length(8),      // Severity
        Constraint::Length(22),     // Status (restored to 22)
        Constraint::Percentage(45), // Description (increased from 35 to use more space)
        Constraint::Length(7),      // Issues (increased from 6)
        Constraint::Length(20),     // Created (increased from 19)
        Constraint::Length(20),     // Last Updated (increased from 19)
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Cases (↑/↓ to navigate, Enter to view details)"),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    // Use standard table rendering without viewport adjustments
    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_sidebar(f: &mut Frame, area: Rect, app: &App) {
    let sidebar_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Severity summary with filters
            Constraint::Length(8),  // Status summary
            Constraint::Min(5),     // Filters help
        ])
        .split(area);

    // Severity summary
    draw_severity_summary(f, sidebar_chunks[0], app);

    // Status summary
    draw_status_summary(f, sidebar_chunks[1], app);

    // Filter help
    draw_filter_help(f, sidebar_chunks[2], app);
}

fn draw_severity_summary(f: &mut Frame, area: Rect, app: &App) {
    let severity_counts = app.get_severity_counts();
    
    // Show total incidents and actual severity values
    let total_incidents = app.incidents.len();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Total: ", Style::default().fg(Color::Gray)),
            Span::styled(total_incidents.to_string(), Style::default().fg(Color::White)),
        ]),
    ];
    
    // If we have incidents but no severity counts, show what severity values we actually have
    if total_incidents > 0 && severity_counts.is_empty() {
        lines.push(Line::from("No severity data found"));
        // Show first few actual severity values for troubleshooting
        for (i, incident) in app.incidents.iter().take(3).enumerate() {
            lines.push(Line::from(format!("#{}: '{}'", i+1, incident.severity)));
        }
    } else {
        // Show standard severity breakdown
        for &severity in ["Critical", "High", "Medium", "Low"].iter() {
            let count = severity_counts.get(severity)
                .or_else(|| severity_counts.get(&severity.to_lowercase()))
                .or_else(|| severity_counts.get(&severity.to_uppercase()))
                .unwrap_or(&0);
                
            let style = match severity.to_lowercase().as_str() {
                "critical" => Style::default().fg(Color::Red),
                "high" => Style::default().fg(Color::LightRed),
                "medium" => Style::default().fg(Color::Yellow),
                "low" => Style::default().fg(Color::Green),
                _ => Style::default().fg(Color::White),
            };

            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", severity), style),
                Span::raw(count.to_string()),
            ]));
        }
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Severity").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn draw_status_summary(f: &mut Frame, area: Rect, app: &App) {
    let now = chrono::Utc::now();
    let next_poll = app.next_poll_time.unwrap_or(now);
    let seconds_until_poll = (next_poll - now).num_seconds().max(0);
    
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Next poll in: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{}s", seconds_until_poll),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            ),
        ]),
        Line::from(""),
    ];
    
    // Add polling status information
    let poll_status = if seconds_until_poll > 60 {
        format!("Backoff mode ({}m {}s)", seconds_until_poll / 60, seconds_until_poll % 60)
    } else if seconds_until_poll > 30 {
        "Standard polling".to_string()
    } else {
        "Active polling".to_string()
    };
    
    lines.push(Line::from(vec![
        Span::styled("Mode: ", Style::default().fg(Color::Gray)),
        Span::styled(poll_status, Style::default().fg(Color::White)),
    ]));
    
    // Add API performance info
    let api_calls = app.api_calls.len();
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("API calls (60s): ", Style::default().fg(Color::Gray)),
        Span::styled(api_calls.to_string(), Style::default().fg(Color::Green)),
    ]));
    
    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Polling Status").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn draw_filter_help(f: &mut Frame, area: Rect, app: &App) {
    let mut filter_text = vec![Line::from("Filters:"), Line::from("")];

    if let Some(ref severity) = app.severity_filter {
        filter_text.push(Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(Color::Yellow)),
            Span::raw(severity),
        ]));
    }

    if let Some(ref status) = app.status_filter {
        filter_text.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Yellow)),
            Span::raw(status),
        ]));
    }

    if app.severity_filter.is_none() && app.status_filter.is_none() {
        filter_text.push(Line::from(Span::styled(
            "None active",
            Style::default().fg(Color::Gray),
        )));
    }

    filter_text.push(Line::from(""));
    filter_text.push(Line::from("Keys:"));
    filter_text.push(Line::from("1-4: Filter severity"));
    filter_text.push(Line::from("s: Filter status"));
    filter_text.push(Line::from("c: Clear filters"));

    let paragraph = Paragraph::new(filter_text)
        .block(
            Block::default()
                .title("Filters & Controls")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Status message
    let status_style = if app.is_error {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Green)
    };

    // Show instance endpoint and status message
    let status_text = format!("Instance: {} | {}", 
        app.tenant_url.as_deref().unwrap_or(""), 
        app.status_message);
    let status = Paragraph::new(status_text)
        .style(status_style)
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[0]);

    // Controls help
    let help_text =
        "↑↓: Navigate | Enter: Details | Esc/Back: Return | 1-4: Filter Severity | s: Status | c: Clear | q: Quit";
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(help, chunks[1]);
}



fn draw_drill_down_header(f: &mut Frame, area: Rect, app: &App) {
    let title = if let Some(incident) = app.get_selected_incident() {
        format!("│XDRTop - Cortex XDR Case Monitor v{} - Case Details: {}", env!("CARGO_PKG_VERSION"), incident.id)
    } else {
        format!("│XDRTop - Cortex XDR Case Monitor v{} - Case Details", env!("CARGO_PKG_VERSION"))
    };

    let header = Paragraph::new(title)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, area);
}

fn draw_incident_details(f: &mut Frame, area: Rect, app: &App) {
    if let Some(incident) = app.get_selected_incident() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(12), // Case summary - increased to show description
                Constraint::Length(5),  // MITRE ATT&CK info
                Constraint::Min(10),    // Issues details
            ])
            .split(area);

        // Case summary
        draw_incident_summary(f, chunks[0], incident);
        
        // MITRE ATT&CK information
        draw_mitre_info(f, chunks[1], incident);

        // Issues details
        draw_alerts_details(f, chunks[2], incident);
    } else {
        let error = Paragraph::new("No case selected")
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL).title("Error"));
        f.render_widget(error, area);
    }
}

fn draw_incident_summary(f: &mut Frame, area: Rect, incident: &Incident) {
    let summary_text = vec![
        Line::from(vec![
            Span::styled(
                "ID: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&incident.id),
        ]),
        Line::from(vec![
            Span::styled(
                "Severity: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&incident.severity, get_severity_style(&incident.severity)),
        ]),
        Line::from(vec![
            Span::styled(
                "Status: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&incident.status),
        ]),
        Line::from(vec![
            Span::styled(
                "Created: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                incident
                    .creation_time
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Last Updated: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                incident.last_updated
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "".to_string())
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Issue Count: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(incident.alert_count.to_string()),
        ]),
        Line::from(vec![Span::styled(
            "Description: ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(Span::raw(&incident.description)),
    ];

    let summary = Paragraph::new(summary_text)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Case Summary"));
    f.render_widget(summary, area);
}

fn draw_mitre_info(f: &mut Frame, area: Rect, incident: &Incident) {
    // Collect MITRE data from incident first, then fallback to alert-level data
    let mut tactics = incident.mitre_tactics.clone();
    let mut techniques = incident.mitre_techniques.clone();
    
    // If incident-level MITRE data is empty, aggregate from alerts
    if tactics.is_empty() && techniques.is_empty() && !incident.alerts.is_empty() {
        let mut all_tactics = std::collections::HashSet::new();
        let mut all_techniques = std::collections::HashSet::new();
        
        for alert in &incident.alerts {
            all_tactics.extend(alert.mitre_tactics.iter().cloned());
            all_techniques.extend(alert.mitre_techniques.iter().cloned());
        }
        
        tactics = all_tactics.into_iter().collect();
        techniques = all_techniques.into_iter().collect();
    }
    
    let tactics_text = if tactics.is_empty() {
        "No MITRE ATT&CK framework data returned".to_string()
    } else {
        tactics.join(", ")
    };
    
    let techniques_text = if techniques.is_empty() {
        "No MITRE ATT&CK framework data returned".to_string() 
    } else {
        techniques.join(", ")
    };

    let mitre_info = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("MITRE Tactics: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(tactics_text),
        ]),
        Line::from(vec![
            Span::styled("MITRE Techniques: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::raw(techniques_text),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).title("MITRE ATT&CK Framework"));
    
    f.render_widget(mitre_info, area);
}

fn draw_alerts_details(f: &mut Frame, area: Rect, incident: &Incident) {
    // Display actual alert/issue details from the API
    let alert_items: Vec<ListItem> = if incident.alerts.is_empty() {
        if incident.alert_count == 0 {
            vec![
                ListItem::new(Line::from(vec![
                    Span::styled("No issues found for this case", Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC)),
                ])),
                ListItem::new(Line::from("")),
                ListItem::new(Line::from(vec![
                    Span::styled("This case shows 0 issues in the summary.", Style::default().fg(Color::Gray)),
                ])),
                ListItem::new(Line::from(vec![
                    Span::styled("The case may be a false positive or already resolved.", Style::default().fg(Color::Gray)),
                ])),
            ]
        } else {
            vec![
                ListItem::new(Line::from(vec![
                    Span::styled("Issue details not available", Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC)),
                ])),
                ListItem::new(Line::from("")),
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("Case shows {} issue(s) but details couldn't be loaded", incident.alert_count),
                        Style::default().fg(Color::Gray),
                    ),
                ])),
                ListItem::new(Line::from(vec![
                    Span::styled("This may be due to API permissions or network issues.", Style::default().fg(Color::Gray)),
                ])),
            ]
        }
    } else {
        let mut items = vec![
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("Individual Issues ({} total):", incident.alerts.len()),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ])),
            ListItem::new(Line::from("")),
        ];

        for (i, alert) in incident.alerts.iter().enumerate() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    format!("Issue {}: ", i + 1),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&alert.name),
            ])));
            
            items.push(ListItem::new(Line::from(vec![
                Span::styled("  Severity: ", Style::default().fg(Color::Gray)),
                Span::styled(&alert.severity, get_severity_style(&alert.severity)),
            ])));
            
            items.push(ListItem::new(Line::from(vec![
                Span::styled("  Category: ", Style::default().fg(Color::Gray)),
                Span::raw(&alert.category),
            ])));
            
            if let Some(description) = &alert.description {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Description: ", Style::default().fg(Color::Gray)),
                    Span::raw(description),
                ])));
            }
            
            if let Some(source) = &alert.source {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Source: ", Style::default().fg(Color::Gray)),
                    Span::raw(source),
                ])));
            }
            
            if let Some(user_name) = &alert.user_name {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  User: ", Style::default().fg(Color::Gray)),
                    Span::raw(user_name),
                ])));
            }
            
            if let Some(action_pretty) = &alert.action_pretty {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Action: ", Style::default().fg(Color::Gray)),
                    Span::raw(action_pretty),
                ])));
            }
            
            if let Some(host_name) = &alert.host_name {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Host: ", Style::default().fg(Color::Gray)),
                    Span::raw(host_name),
                ])));
            }
            
            if !alert.mitre_tactics.is_empty() {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  MITRE Tactics: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        alert.mitre_tactics.join(", "),
                        Style::default().fg(Color::LightBlue),
                    ),
                ])));
            }
            
            if !alert.mitre_techniques.is_empty() {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  MITRE Techniques: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        alert.mitre_techniques.join(", "),
                        Style::default().fg(Color::LightGreen),
                    ),
                ])));
            }
            
            items.push(ListItem::new(Line::from("")));
        }

        items
    };

    let alerts_list = List::new(alert_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Issues ({})", incident.alert_count)),
    );
    f.render_widget(alerts_list, area);
}

fn draw_drill_down_status_bar(f: &mut Frame, area: Rect, _app: &App) {
    let help_text = "Press 'Esc' or 'Backspace' to return to main view | 'q' to quit application";
    let status = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Navigation"));
    f.render_widget(status, area);
}

fn get_severity_style(severity: &str) -> Style {
    // Cache-friendly style lookup with early returns for performance
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "high" => Style::default().fg(Color::LightRed),
        "medium" => Style::default().fg(Color::Yellow),
        "low" => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::White),
    }
}

fn get_status_style(status: &str) -> Style {
    // Cache-friendly style lookup with early returns for performance
    match status.to_ascii_lowercase().as_str() {
        "new" => Style::default().fg(Color::LightBlue),
        "under_investigation" => Style::default().fg(Color::Yellow),
        "resolved" => Style::default().fg(Color::Green),
        "closed" => Style::default().fg(Color::Gray),
        _ => Style::default().fg(Color::White),
    }
}
