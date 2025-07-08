use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Write};
use tokio::time::{interval, Duration};

mod api;
mod config;
mod incidents;
mod ui;

use api::XdrClient;
use config::Config;
use incidents::IncidentStore;
use ui::App;

#[derive(Parser)]
#[command(name = "xdrtop")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "XDRTop - A CLI tool to monitor Cortex XDR incidents in real-time")]
struct Cli {
    /// Initialise configuration
    #[arg(long)]
    init_config: bool,
    /// Enable debug logging to debug_output.log
    #[arg(long)]
    debug: bool,

    /// Test API connection and show response
    #[arg(long)]
    test_api: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.init_config {
        config::init_config().await?;
        return Ok(());
    }

    let mut config = Config::load().await?;
    let client = XdrClient::new(config.clone(), cli.debug);
    let debug_enabled = cli.debug;

    if cli.test_api {
        match client.get_incidents().await {
            Ok(_incidents) => {
            }
            Err(_e) => {
            }
        }
        return Ok(());
    }

    let mut incident_store = IncidentStore::new();
    let mut app = App::new();
    
    // Set tenant URL for display
    app.set_tenant_url(config.tenant_url.clone());

    // Setup terminal - disable mouse capture to allow text selection
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?; // Removed EnableMouseCapture
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main application loop
    // Apply saved filter settings
    let (severity_filter, status_filter) = (
        config.filter_settings.severity_filter.clone(),
        config.filter_settings.status_filter.clone(),
    );
    app.set_filter_settings(severity_filter, status_filter);

    let result = run_app(&mut terminal, &mut app, &client, &mut incident_store, &mut config, debug_enabled).await;

    // Restore terminal - no need to disable mouse capture since we didn't enable it
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?; // Removed DisableMouseCapture
    terminal.show_cursor()?;

    if let Err(_err) = result {
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    client: &XdrClient,
    incident_store: &mut IncidentStore,
    config: &mut Config,
    debug_enabled: bool,
) -> Result<()> {
    let mut poll_interval = interval(client.get_poll_interval());
    let mut should_exit = false;
    let mut last_poll_duration = client.get_poll_interval();
    let startup_time = std::time::Instant::now();
    let _memory_cleanup_counter = 0;
    
    // Set initial next poll time
    app.set_next_poll_time(last_poll_duration);
    
    // Force initial render to ensure app starts in main view
    terminal.draw(|f| ui::draw(f, app))?;

    loop {
        tokio::select! {
            _ = poll_interval.tick() => {
                // Poll for incidents with improved error handling
                match client.get_incidents().await {
                    Ok(incidents) => {
                        app.record_api_call();
                        
                        // Only update if we have new data (empty vec indicates 304 Not Modified)
                        if !incidents.is_empty() {
                            incident_store.update(incidents);
                            app.set_incidents(incident_store.get_all());
                        }
                        
                        let error_count = client.get_error_count();
                        let status_msg = if error_count > 0 {
                            format!("Connected (recovered from {} errors)", error_count)
                        } else {
                            "Connected".to_string()
                        };
                        app.set_status(status_msg, false);

                        // Adaptive polling - adjust interval based on API performance
                        let new_interval = client.get_poll_interval();
                        if new_interval != last_poll_duration {
                            poll_interval = interval(new_interval);
                            last_poll_duration = new_interval;
                        }
                        
                        // Update next poll time for countdown display
                        app.set_next_poll_time(new_interval);
                    }
                    Err(_e) => {
                        app.record_api_call();
                        let error_count = client.get_error_count();
                        let status_msg = format!("Connection error (attempt {})", error_count);
                        app.set_status(status_msg, true);

                        // Adaptive polling with exponential backoff
                        let new_interval = client.get_poll_interval();
                        if new_interval != last_poll_duration {
                            poll_interval = interval(new_interval);
                            last_poll_duration = new_interval;
                            
                            if error_count > 3 {
                                let backoff_seconds = new_interval.as_secs();
                                app.set_status(
                                    format!("Multiple errors. Backing off to {}s", backoff_seconds),
                                    true
                                );
                            }
                        }
                        
                        // Update next poll time for countdown display
                        app.set_next_poll_time(new_interval);
                    }
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                // Check for user input with reduced polling for better responsiveness
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        // Only process key press events, ignore key release events (Windows issue)
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }
                        
                        // Windows key debouncing to prevent double events
                        if !app.should_process_key() {
                            continue;
                        }
                        
                        match key.code {
                            KeyCode::Char('q') => {
                                // Save filter settings before exiting
                                let (severity_filter, status_filter) = app.get_filter_settings();
                                if let Err(_) = config.update_filter_settings(severity_filter, status_filter).await {
                                    // If saving fails, continue exiting anyway
                                }
                                should_exit = true;
                            }
                            KeyCode::Esc | KeyCode::Backspace => {
                                if app.is_drill_down_mode() {
                                    app.exit_drill_down();
                                }
                                // Only 'q' exits the application, Esc/Backspace only exit drill-down mode
                            }
                            KeyCode::Enter => {
                                // Prevent accidental Enter activation during startup on Windows
                                if startup_time.elapsed().as_millis() > 500 && 
                                   !app.is_drill_down_mode() && 
                                   !app.filtered_incidents.is_empty() {
                                    
                                    // Get incident ID BEFORE entering drill-down mode
                                    let incident_id = if let Some(selected_idx) = app.table_state.selected() {
                                        if selected_idx < app.filtered_incidents.len() {
                                            let id = app.filtered_incidents[selected_idx].id.clone();

                                            Some(id)
                                        } else {

                                            None
                                        }
                                    } else {

                                        None
                                    };
                                    
                                    // Fetch alert details FIRST, then enter drill-down with complete data
                                    if let Some(id) = incident_id {

                                        // Show immediate loading indicator before any operations
                                        app.set_status("⏳ Loading issue details - please wait...".to_string(), false);
                                        
                                        // Force UI update to show loading message immediately
                                        terminal.draw(|f| ui::draw(f, app))?;
                                        
                                        // Prepare for drill-down and fetch alert details
                                        app.prepare_for_drill_down(&id);
                                        app.enter_drill_down();
                                        
                                        // Log drill-down attempt for debugging (only when --debug flag is enabled)
                                        if debug_enabled {
                                            safe_debug_log(format!(
                                                "\n=== DRILL-DOWN ATTEMPT FOR INCIDENT {} ===\nTime: {:?}",
                                                id, std::time::SystemTime::now()
                                            ));
                                        }
                                        
                                        // Fetch alerts for this incident with timeout
                                        let alert_fetch_timeout = tokio::time::Duration::from_secs(10);
                                        match tokio::time::timeout(alert_fetch_timeout, client.get_incident_alerts(&id)).await {
                                            Ok(Ok(alerts)) => {
                                                if debug_enabled {
                                                    safe_debug_log(format!(
                                                        "SUCCESS: Fetched {} alerts for incident {}", 
                                                        alerts.len(), id
                                                    ));
                                                }
                                                app.update_selected_incident_alerts(alerts.clone());
                                                app.set_status(format!("✅ Loaded {} issue details", alerts.len()), false);
                                            }
                                            Ok(Err(e)) => {
                                                if debug_enabled {
                                                    safe_debug_log(format!(
                                                        "ERROR: Alert API failed for incident {}: {}", 
                                                        id, e
                                                    ));
                                                }
                                                app.set_status(format!("Alert API error: {}", e), true);
                                            }
                                            Err(_timeout) => {
                                                app.set_status("⏰ Alert loading timed out after 10s".to_string(), true);
                                                if debug_enabled {
                                                    safe_debug_log(format!("TIMEOUT: Alert fetch timed out for incident {}", id));
                                                }
                                            }
                                        }
                                    } else {

                                    }
                                }
                            }
                            KeyCode::Up => {
                                if !app.is_drill_down_mode() {
                                    app.previous();
                                }
                            }
                            KeyCode::Down => {
                                if !app.is_drill_down_mode() {
                                    app.next();
                                }
                            }
                            KeyCode::Char('1') => {
                                if !app.is_drill_down_mode() {
                                    app.toggle_severity_filter("Critical".to_string());
                                }
                            }
                            KeyCode::Char('2') => {
                                if !app.is_drill_down_mode() {
                                    app.toggle_severity_filter("High".to_string());
                                }
                            }
                            KeyCode::Char('3') => {
                                if !app.is_drill_down_mode() {
                                    app.toggle_severity_filter("Medium".to_string());
                                }
                            }
                            KeyCode::Char('4') => {
                                if !app.is_drill_down_mode() {
                                    app.toggle_severity_filter("Low".to_string());
                                }
                            }
                            KeyCode::Char('s') => {
                                if !app.is_drill_down_mode() {
                                    app.cycle_status_filter();
                                }
                            }
                            KeyCode::Char('c') => {
                                if !app.is_drill_down_mode() {
                                    app.clear_filters();
                                }
                            }

                            _ => {}
                        }
                    }
                }
            }
        }

        // Render the UI
        terminal.draw(|f| ui::draw(f, app))?;

        if should_exit {
            break;
        }
    }

    Ok(())
}

/// Safe debug logging helper with proper resource management
fn safe_debug_log(message: String) {
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
