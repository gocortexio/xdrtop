use chrono::{DateTime, Utc};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use std::collections::{HashMap, VecDeque};

use crate::cases::{Case, IssueDetail};

pub struct App {
    pub cases: Vec<Case>,
    pub filtered_cases: Vec<Case>,
    pub table_state: TableState,
    pub status_message: String,
    pub is_error: bool,
    pub last_update: chrono::DateTime<chrono::Utc>,
    pub drill_down_mode: bool,
    pub selected_case: Option<Case>,
    pub severity_filter: Option<String>,
    pub status_filter: Option<String>,
    pub domain_filter: Option<String>,
    pub observed_domains: Vec<String>,
    pub api_calls: VecDeque<DateTime<Utc>>,
    pub next_poll_time: Option<DateTime<Utc>>,
    pub tenant_url: Option<String>,
    pub loading_large_dataset: bool,
    pub last_key_time: std::time::Instant,
}

impl App {
    pub fn new() -> Self {
        Self {
            cases: Vec::new(),
            filtered_cases: Vec::new(),
            table_state: TableState::default(),
            status_message: String::new(),
            is_error: false,
            last_update: chrono::Utc::now(),
            drill_down_mode: false,
            selected_case: None,
            severity_filter: None,
            status_filter: None,
            domain_filter: None,
            observed_domains: Vec::new(),
            api_calls: VecDeque::new(),
            next_poll_time: None,
            tenant_url: None,
            loading_large_dataset: false,
            last_key_time: std::time::Instant::now(),
        }
    }

    pub fn set_cases(&mut self, cases: &[Case]) {
        // Handle large datasets (>500 cases) with optimised loading
        if cases.len() > 500 {
            self.loading_large_dataset = true;
            self.status_message = format!("Loading {} cases...", cases.len());
        }
        
        // Skip redundant operations if cases haven't changed
        if cases.len() == self.cases.len() && 
           cases.iter().zip(&self.cases).all(|(a, b)| a.id == b.id) {
            self.loading_large_dataset = false;
            return;
        }
        
        // Pre-allocate vectors for large datasets to avoid reallocations
        if cases.len() > self.cases.capacity() {
            self.cases.reserve(cases.len());
        }
        
        // Memory optimization: avoid unnecessary copying by using clone_from when possible
        if self.cases.len() == cases.len() {
            // Reuse existing capacity and update in-place
            self.cases.clone_from_slice(cases);
        } else {
            // Only allocate new vector when size changes
            self.cases = cases.to_vec();
        }
        self.apply_filters();
        self.last_update = chrono::Utc::now();
        self.loading_large_dataset = false;

        // Reset selection if we have fewer cases than before
        let case_count = self.filtered_cases.len();
        if let Some(selected) = self.table_state.selected() {
            if selected >= case_count && case_count > 0 {
                self.table_state.select(Some(case_count - 1));
            }
        } else if case_count > 0 && !self.drill_down_mode {
            // Only auto-select on first load when we have no selection and not in drill-down mode
            // Don't auto-select on Windows to prevent auto-entering case details
            #[cfg(not(target_os = "windows"))]
            self.table_state.select(Some(0));
        }
    }

    fn apply_filters(&mut self) {
        // Update observed domains from current cases
        self.update_observed_domains();

        // Memory optimisation: avoid unnecessary cloning and allocations
        if self.severity_filter.is_none() && self.status_filter.is_none() && self.domain_filter.is_none() {
            // No filters active - avoid cloning when possible
            if self.filtered_cases.len() != self.cases.len() {
                self.filtered_cases.clone_from(&self.cases);
            }
            return;
        }

        // Clear and pre-allocate with estimated capacity to avoid reallocations
        self.filtered_cases.clear();
        let estimated_capacity = self.cases.len() / 2;
        if self.filtered_cases.capacity() < estimated_capacity {
            self.filtered_cases.reserve(estimated_capacity);
        }

        for case in &self.cases {
            let mut include = true;

            if let Some(ref severity_filter) = self.severity_filter {
                if !case.severity.eq_ignore_ascii_case(severity_filter) {
                    include = false;
                }
            }

            if include {
                if let Some(ref status_filter) = self.status_filter {
                    if !case.status.eq_ignore_ascii_case(status_filter) {
                        include = false;
                    }
                }
            }

            if include {
                if let Some(ref domain_filter) = self.domain_filter {
                    match &case.case_domain {
                        Some(domain) if domain.eq_ignore_ascii_case(domain_filter) => {}
                        _ => include = false,
                    }
                }
            }

            if include {
                self.filtered_cases.push(case.clone());
            }
        }
    }

    fn update_observed_domains(&mut self) {
        let mut domain_set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for case in &self.cases {
            if let Some(ref domain) = case.case_domain {
                if !domain.is_empty() {
                    domain_set.insert(domain.clone());
                }
            }
        }
        self.observed_domains = domain_set.into_iter().collect();
        self.observed_domains.sort();
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
        self.domain_filter = None;
        self.apply_filters();
    }

    pub fn cycle_domain_filter(&mut self) {
        if self.observed_domains.is_empty() {
            return;
        }

        let current_index = self
            .domain_filter
            .as_ref()
            .and_then(|domain| self.observed_domains.iter().position(|d| d == domain))
            .unwrap_or(self.observed_domains.len() - 1);

        let next_index = (current_index + 1) % self.observed_domains.len();
        if next_index == 0 && self.domain_filter.is_some() {
            self.domain_filter = None;
        } else {
            self.domain_filter = Some(self.observed_domains[next_index].clone());
        }
        self.apply_filters();
        self.table_state.select(Some(0));
    }

    pub fn cycle_status_filter(&mut self) {
        // Get unique statuses from actual data
        let mut unique_statuses: Vec<String> = self
            .cases
            .iter()
            .map(|case| case.status.clone())
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

    #[allow(dead_code)]
    pub fn cleanup_memory(&mut self) {
        // Clean old API call records
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(120);
        self.api_calls.retain(|&time| time >= cutoff);

        // Shrink capacity if vectors are oversized (more than 2x current size)
        if self.cases.capacity() > self.cases.len() * 2 && self.cases.capacity() > 100 {
            self.cases.shrink_to_fit();
        }

        if self.filtered_cases.capacity() > self.filtered_cases.len() * 2 && self.filtered_cases.capacity() > 100 {
            self.filtered_cases.shrink_to_fit();
        }
    }

    pub fn next(&mut self) {
        if self.filtered_cases.is_empty() {
            return;
        }

        let i = match self.table_state.selected() {
            Some(i) => {
                if i >= self.filtered_cases.len() - 1 {
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
        if self.filtered_cases.is_empty() {
            return;
        }

        let i = match self.table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_cases.len() - 1
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
        // Use filtered cases if filters are active, otherwise use all cases
        let cases_to_count = if self.severity_filter.is_some() || self.status_filter.is_some() {
            &self.filtered_cases
        } else {
            &self.cases
        };
        
        for case in cases_to_count {
            *counts.entry(case.severity.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn enter_drill_down(&mut self) {
        // Only enter drill-down if we have cases and a valid selection
        if self.filtered_cases.is_empty() {
            return;
        }
        
        if let Some(selected_idx) = self.table_state.selected() {
            if selected_idx < self.filtered_cases.len() {
                let case = &self.filtered_cases[selected_idx];

                self.selected_case = Some(case.clone());
                self.drill_down_mode = true;
            }
        }
    }

    pub fn exit_drill_down(&mut self) {
        self.drill_down_mode = false;
        self.selected_case = None;
        
        // Ensure we have a valid selection when returning to main view
        if !self.filtered_cases.is_empty() && self.table_state.selected().is_none() {
            self.table_state.select(Some(0));
        }
    }

    pub fn is_drill_down_mode(&self) -> bool {
        self.drill_down_mode
    }

    pub fn get_selected_case(&self) -> Option<&Case> {
        self.selected_case.as_ref()
    }
    
    pub fn update_selected_case_issues(&mut self, issues: Vec<IssueDetail>) {
        if let Some(ref mut case) = self.selected_case {
            // Only update issues, preserve the original issue_count from the main cases API
            // The main cases API has the authoritative count, individual issues API may be incomplete
            case.issues = issues;
        }
    }
    
    pub fn prepare_for_drill_down(&mut self, case_id: &str) {
        // Find and clone the case to prepare for drill-down mode
        if let Some(case) = self.filtered_cases.iter().find(|c| c.id == case_id) {
            self.selected_case = Some(case.clone());
        }
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Safety check: if we're in drill-down mode but have no selected case, exit drill-down
    if app.is_drill_down_mode() && app.get_selected_case().is_none() {
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

    // Cases table
    draw_cases_table(f, content_chunks[0], app);

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
            Constraint::Min(10),   // Case details
            Constraint::Length(3), // Status bar
        ])
        .split(size);

    // Header with drill-down indicator
    draw_drill_down_header(f, chunks[0], app);

    // Case details
    draw_case_details(f, chunks[1], app);

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
    let total_cases = app.cases.len();
    let filtered_count = app.filtered_cases.len();
    let last_update = app.last_update.format("%H:%M:%S").to_string();

    let stats_text = if total_cases != filtered_count {
        format!("Cases: {filtered_count}/{total_cases} | Updated: {last_update}")
    } else {
        format!("Total Cases: {total_cases} | Updated: {last_update}")
    };

    let stats = Paragraph::new(stats_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Stats"));
    f.render_widget(stats, header_chunks[1]);
}

fn draw_cases_table(f: &mut Frame, area: Rect, app: &mut App) {
    let header_cells = [
        "ID",
        "Severity", 
        "Status",
        "Domain",
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
    let rows = app.filtered_cases.iter().map(|case| {
        // Use cached style functions
        let severity_style = get_severity_style(&case.severity);
        let status_style = get_status_style(&case.status);

        // Optimised string operations - use owned strings to avoid borrow issues
        let id_display = case.id.chars().take(10).collect::<String>();
        let issue_count = case.issue_count.to_string();
        let formatted_created = case.creation_time.format("%Y-%m-%d %H:%M:%S").to_string();
        let formatted_updated = case.last_updated
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();

        let domain_display = case.case_domain.clone().unwrap_or_default();

        Row::new(vec![
            Cell::from(id_display),
            Cell::from(case.severity.clone()).style(severity_style),
            Cell::from(case.status.clone()).style(status_style),
            Cell::from(domain_display),
            Cell::from(case.truncated_description(60)), // Reduced to make room for domain column
            Cell::from(issue_count),
            Cell::from(formatted_created),
            Cell::from(formatted_updated),
        ])
    });

    let widths = [
        Constraint::Length(12),     // ID
        Constraint::Length(8),      // Severity
        Constraint::Length(22),     // Status
        Constraint::Length(12),     // Domain
        Constraint::Percentage(30), // Description (reduced to make room for domain)
        Constraint::Length(7),      // Issues
        Constraint::Length(20),     // Created
        Constraint::Length(20),     // Last Updated
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Cases (Up/Down to navigate, Enter to view details)"),
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
    
    // Show total cases and actual severity values
    let total_cases = app.cases.len();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Total: ", Style::default().fg(Color::Gray)),
            Span::styled(total_cases.to_string(), Style::default().fg(Color::White)),
        ]),
    ];
    
    // If we have cases but no severity counts, show what severity values we actually have
    if total_cases > 0 && severity_counts.is_empty() {
        lines.push(Line::from("No severity data found"));
        // Show first few actual severity values for troubleshooting
        for (i, case) in app.cases.iter().take(3).enumerate() {
            lines.push(Line::from(format!("#{}: '{}'", i+1, case.severity)));
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
                Span::styled(format!("{severity}: "), Style::default().fg(Color::Gray)),
                Span::styled(count.to_string(), style),
            ]));
        }
    }

    let severity_summary = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Severity"));
    f.render_widget(severity_summary, area);
}

fn draw_status_summary(f: &mut Frame, area: Rect, app: &App) {
    let poll_interval = std::time::Duration::from_secs(120);
    let poll_secs = poll_interval.as_secs();
    let next_poll_text = app.next_poll_time
        .map(|time| {
            let now = chrono::Utc::now();
            if time > now {
                let diff_secs = (time - now).num_seconds();
                format!("{diff_secs}s")
            } else {
                "now".to_string()
            }
        })
        .unwrap_or_else(|| format!("{poll_secs}s"));

    let lines = vec![
        Line::from(vec![
            Span::styled("Next poll in: ", Style::default().fg(Color::Gray)),
            Span::styled(next_poll_text, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(Color::Gray)),
            Span::styled("Backoff mode", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(format!("({})", format_duration(poll_interval)), Style::default().fg(Color::Gray)),
        ]),
    ];

    let status = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Polling Status"));
    f.render_widget(status, area);
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs >= 60 {
        let mins = secs / 60;
        let remaining_secs = secs % 60;
        format!("{mins}m {remaining_secs}s")
    } else {
        format!("{secs}s")
    }
}

fn draw_filter_help(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Filters:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
    ];

    // Show active filters
    if app.severity_filter.is_some() || app.status_filter.is_some() || app.domain_filter.is_some() {
        if let Some(ref filter) = app.severity_filter {
            lines.push(Line::from(vec![
                Span::styled("Severity: ", Style::default().fg(Color::Gray)),
                Span::styled(filter, Style::default().fg(Color::Cyan)),
            ]));
        }
        if let Some(ref filter) = app.status_filter {
            lines.push(Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::Gray)),
                Span::styled(filter, Style::default().fg(Color::Cyan)),
            ]));
        }
        if let Some(ref filter) = app.domain_filter {
            lines.push(Line::from(vec![
                Span::styled("Domain: ", Style::default().fg(Color::Gray)),
                Span::styled(filter, Style::default().fg(Color::Cyan)),
            ]));
        }
    } else {
        lines.push(Line::from(vec![
            Span::styled("None active", Style::default().fg(Color::Gray)),
        ]));
    }

    let help = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Filters & Controls"));
    f.render_widget(help, area);
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let status_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Status message
    let status_style = if app.is_error {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Green)
    };

    let instance_text = app.tenant_url.clone().unwrap_or_else(|| "Unknown".to_string());
    let status = Paragraph::new(format!("Instance: {instance_text}"))
        .style(status_style)
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, status_chunks[0]);

    // Controls
    let controls = Paragraph::new("Up/Down: Navigate | Enter: Details | q: Quit")
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(controls, status_chunks[1]);
}

fn draw_drill_down_header(f: &mut Frame, area: Rect, app: &App) {
    let case_id = app.get_selected_case()
        .map(|c| c.id.clone())
        .unwrap_or_else(|| "Unknown".to_string());
        
    let header_text = format!("Case Details - ID: {case_id}");
    let header = Paragraph::new(header_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title("Drill-Down View"));
    f.render_widget(header, area);
}

fn draw_case_details(f: &mut Frame, area: Rect, app: &App) {
    if let Some(case) = app.get_selected_case() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(12), // Case summary
                Constraint::Length(6),  // MITRE info
                Constraint::Min(10),    // Issues details
            ])
            .split(area);

        // Case summary
        draw_case_summary(f, chunks[0], case);

        // MITRE ATT&CK information
        draw_mitre_info(f, chunks[1], case);

        // Issues details
        draw_issues_details(f, chunks[2], case);
    } else {
        let error = Paragraph::new("No case selected")
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL).title("Error"));
        f.render_widget(error, area);
    }
}

fn draw_case_summary(f: &mut Frame, area: Rect, case: &Case) {
    let summary_text = vec![
        Line::from(vec![
            Span::styled(
                "Case ID: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&case.id),
        ]),
        Line::from(vec![
            Span::styled(
                "Severity: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&case.severity, get_severity_style(&case.severity)),
        ]),
        Line::from(vec![
            Span::styled(
                "Status: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&case.status, get_status_style(&case.status)),
        ]),
        Line::from(vec![
            Span::styled(
                "Domain: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(case.case_domain.clone().unwrap_or_else(|| "-".to_string())),
        ]),
        Line::from(vec![
            Span::styled(
                "Created: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(case.creation_time.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
        ]),
        Line::from(vec![
            Span::styled(
                "Last Updated: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(
                case.last_updated
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_default()
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "Issue Count: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(case.issue_count.to_string()),
        ]),
        Line::from(vec![Span::styled(
            "Description: ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(Span::raw(&case.description)),
    ];

    let summary = Paragraph::new(summary_text)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Case Summary"));
    f.render_widget(summary, area);
}

fn draw_mitre_info(f: &mut Frame, area: Rect, case: &Case) {
    // MITRE data comes from the case level, not individual issues
    // The issue/search API does not return MITRE data directly
    let tactics = &case.mitre_tactics;
    let techniques = &case.mitre_techniques;
    
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

fn draw_issues_details(f: &mut Frame, area: Rect, case: &Case) {
    // Display actual issue details from the API
    let issue_items: Vec<ListItem> = if case.issues.is_empty() {
        if case.issue_count == 0 {
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
                        format!("Case shows {} issue(s) but details couldn't be loaded", case.issue_count),
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
                    format!("Individual Issues ({} total):", case.issues.len()),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ])),
            ListItem::new(Line::from("")),
        ];

        for (i, issue) in case.issues.iter().enumerate() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    format!("Issue {}: ", i + 1),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&issue.name),
            ])));
            
            items.push(ListItem::new(Line::from(vec![
                Span::styled("  Severity: ", Style::default().fg(Color::Gray)),
                Span::styled(&issue.severity, get_severity_style(&issue.severity)),
            ])));
            
            items.push(ListItem::new(Line::from(vec![
                Span::styled("  Category: ", Style::default().fg(Color::Gray)),
                Span::raw(&issue.category),
            ])));
            
            if let Some(ref description) = issue.description {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Description: ", Style::default().fg(Color::Gray)),
                    Span::raw(description),
                ])));
            }
            
            if let Some(ref remediation) = issue.remediation {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Remediation: ", Style::default().fg(Color::Gray)),
                    Span::raw(remediation),
                ])));
            }

            if !issue.asset_names.is_empty() {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Assets: ", Style::default().fg(Color::Gray)),
                    Span::raw(issue.asset_names.join(", ")),
                ])));
            }

            if let Some(ref detection_method) = issue.detection_method {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("  Detection: ", Style::default().fg(Color::Gray)),
                    Span::raw(detection_method),
                ])));
            }
            
            items.push(ListItem::new(Line::from("")));
        }

        items
    };

    let issues_list = List::new(issue_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Issues ({})", case.issue_count)),
    );
    f.render_widget(issues_list, area);
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
