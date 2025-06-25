use chrono::{DateTime, Utc};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use std::collections::{HashMap, VecDeque};

use crate::incidents::Incident;

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
}

impl App {
    pub fn new() -> Self {
        Self {
            incidents: Vec::new(),
            filtered_incidents: Vec::new(),
            table_state: TableState::default(),
            status_message: "Initialising...".to_string(),
            is_error: false,
            last_update: chrono::Utc::now(),
            drill_down_mode: false,
            selected_incident: None,
            severity_filter: None,
            status_filter: None,
            api_calls: VecDeque::new(),
            next_poll_time: None,
            tenant_url: None,
        }
    }

    pub fn set_incidents(&mut self, incidents: &[Incident]) {
        let mut sorted_incidents = incidents.to_vec();
        
        // Optimized ID parsing with caching
        sorted_incidents.sort_by_cached_key(|incident| {
            incident.id.chars()
                .filter(|c| c.is_ascii_digit())
                .fold(0u64, |acc, c| acc * 10 + (c as u8 - b'0') as u64)
        });

        self.incidents = sorted_incidents;
        self.apply_filters();
        self.last_update = chrono::Utc::now();

        // Reset selection if we have fewer incidents than before
        let incident_count = self.filtered_incidents.len();
        if let Some(selected) = self.table_state.selected() {
            if selected >= incident_count && incident_count > 0 {
                self.table_state.select(Some(incident_count - 1));
            }
        } else if incident_count > 0 {
            self.table_state.select(Some(0));
        }
    }

    fn apply_filters(&mut self) {
        self.filtered_incidents = self
            .incidents
            .iter()
            .filter(|incident| {
                if let Some(ref severity_filter) = self.severity_filter {
                    if !incident.severity.eq_ignore_ascii_case(severity_filter) {
                        return false;
                    }
                }
                if let Some(ref status_filter) = self.status_filter {
                    if !incident.status.eq_ignore_ascii_case(status_filter) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
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

    pub fn record_api_call(&mut self) {
        let now = chrono::Utc::now();
        self.api_calls.push_back(now);

        // Batch cleanup - only clean every 10 calls to reduce overhead
        if self.api_calls.len() % 10 == 0 {
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

    fn get_status_counts(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for incident in &self.incidents {
            *counts.entry(incident.status.clone()).or_insert(0) += 1;
        }
        counts
    }

    pub fn enter_drill_down(&mut self) {
        if let Some(selected_idx) = self.table_state.selected() {
            if selected_idx < self.filtered_incidents.len() {
                self.selected_incident = Some(self.filtered_incidents[selected_idx].clone());
                self.drill_down_mode = true;
            }
        }
    }

    pub fn exit_drill_down(&mut self) {
        self.drill_down_mode = false;
        self.selected_incident = None;
    }

    pub fn is_drill_down_mode(&self) -> bool {
        self.drill_down_mode
    }

    pub fn get_selected_incident(&self) -> Option<&Incident> {
        self.selected_incident.as_ref()
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let size = f.size();

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

    // Title
    let title = Paragraph::new("XDRTop - Cortex XDR Case Monitor")
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

    let rows = app.filtered_incidents.iter().map(|incident| {
        // Use optimized style functions to avoid repeated allocations
        let severity_style = get_severity_style(&incident.severity);
        let status_style = get_status_style(&incident.status);

        Row::new(vec![
            Cell::from(incident.id.chars().take(10).collect::<String>()),
            Cell::from(incident.severity.clone()).style(severity_style),
            Cell::from(incident.status.clone()).style(status_style),
            Cell::from(incident.truncated_description(80)),
            Cell::from(incident.alerts.len().to_string()),
            Cell::from(incident.creation_time.to_rfc3339()),
        ])
    });

    let widths = [
        Constraint::Length(10),     // ID
        Constraint::Length(8),      // Severity
        Constraint::Length(22),     // Status (increased width)
        Constraint::Percentage(50), // Description (adjusted for wider status)
        Constraint::Length(6),      // Issues
        Constraint::Length(19),     // Created
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Cases (↑/↓ to navigate, Enter to view details)"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

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
        app.tenant_url.as_deref().unwrap_or("Not configured"), 
        app.status_message);
    let status = Paragraph::new(status_text)
        .style(status_style)
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[0]);

    // Controls help
    let help_text =
        "↑↓: Navigate | Enter: Details | 1-4: Filter Severity | s: Status | c: Clear | q: Quit";
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(help, chunks[1]);
}

fn draw_drill_down_header(f: &mut Frame, area: Rect, app: &App) {
    let title = if let Some(incident) = app.get_selected_incident() {
        format!("XDRTop - Case Details: {}", incident.id)
    } else {
        "XDRTop - Case Details".to_string()
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
                Constraint::Length(8), // Case summary
                Constraint::Min(10),   // Issues details
            ])
            .split(area);

        // Case summary
        draw_incident_summary(f, chunks[0], incident);

        // Issues details
        draw_alerts_details(f, chunks[1], incident);
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
                "Issue Count: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(incident.alerts.len().to_string()),
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

fn draw_alerts_details(f: &mut Frame, area: Rect, incident: &Incident) {
    let alert_items: Vec<ListItem> = incident
        .alerts
        .iter()
        .enumerate()
        .map(|(i, alert)| {
            let mut alert_text = vec![
                Line::from(vec![
                    Span::styled(
                        format!("Issue {}: ", i + 1),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(&alert.name),
                ]),
                Line::from(vec![
                    Span::styled("  Severity: ", Style::default().fg(Color::Gray)),
                    Span::styled(&alert.severity, get_severity_style(&alert.severity)),
                ]),
                Line::from(vec![
                    Span::styled("  Category: ", Style::default().fg(Color::Gray)),
                    Span::raw(&alert.category),
                ]),
                Line::from(vec![
                    Span::styled("  Source: ", Style::default().fg(Color::Gray)),
                    Span::raw(alert.source.as_deref().unwrap_or("Unknown")),
                ]),
                Line::from(vec![
                    Span::styled("  Host: ", Style::default().fg(Color::Gray)),
                    Span::raw(alert.host_name.as_deref().unwrap_or("Unknown")),
                ]),
            ];

            // Add MITRE tactics
            if !alert.mitre_tactics.is_empty() {
                alert_text.push(Line::from(vec![
                    Span::styled("  MITRE Tactics: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        alert.mitre_tactics.join(", "),
                        Style::default().fg(Color::LightBlue),
                    ),
                ]));
            }

            // Add MITRE techniques
            if !alert.mitre_techniques.is_empty() {
                alert_text.push(Line::from(vec![
                    Span::styled("  MITRE Techniques: ", Style::default().fg(Color::Gray)),
                    Span::styled(
                        alert.mitre_techniques.join(", "),
                        Style::default().fg(Color::LightGreen),
                    ),
                ]));
            }

            alert_text.push(Line::from(""));
            ListItem::new(alert_text)
        })
        .collect();

    let alerts_list = List::new(alert_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Issues ({})", incident.alerts.len())),
    );
    f.render_widget(alerts_list, area);
}

fn draw_drill_down_status_bar(f: &mut Frame, area: Rect, _app: &App) {
    let help_text = "Press 'Esc' or 'Backspace' to return to main view | 'q' to quit";
    let status = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Navigation"));
    f.render_widget(status, area);
}

fn get_severity_style(severity: &str) -> Style {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        "high" => Style::default().fg(Color::LightRed),
        "medium" => Style::default().fg(Color::Yellow),
        "low" => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::White),
    }
}

fn get_status_style(status: &str) -> Style {
    match status.to_ascii_lowercase().as_str() {
        "new" => Style::default().fg(Color::LightBlue),
        "under_investigation" => Style::default().fg(Color::Yellow),
        "resolved" => Style::default().fg(Color::Green),
        "closed" => Style::default().fg(Color::Gray),
        _ => Style::default().fg(Color::White),
    }
}
