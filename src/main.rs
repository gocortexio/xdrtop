use anyhow::Result;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
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
#[command(about = "XDRTop - A CLI tool to monitor Cortex XDR incidents in real-time")]
struct Cli {
    /// Initialise configuration
    #[arg(long)]
    init_config: bool,

    /// Test API connection and show response
    #[arg(long)]
    test_api: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.init_config {
        config::init_config().await?;
        println!("Configuration initialised successfully!");
        return Ok(());
    }

    let config = Config::load().await?;
    let client = XdrClient::new(config.clone());

    if cli.test_api {
        println!("Testing API connection...");
        match client.get_incidents().await {
            Ok(incidents) => {
                println!("✓ API connection successful!");
                println!("Retrieved {} incidents", incidents.len());
            }
            Err(e) => {
                println!("✗ API connection failed:");
                println!("Error: {}", e);
            }
        }
        return Ok(());
    }

    let mut incident_store = IncidentStore::new();
    let mut app = App::new();
    
    // Set tenant URL for display
    app.set_tenant_url(config.tenant_url);

    // Setup terminal - disable mouse capture to allow text selection
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?; // Removed EnableMouseCapture
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main application loop
    let result = run_app(&mut terminal, &mut app, &client, &mut incident_store).await;

    // Restore terminal - no need to disable mouse capture since we didn't enable it
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?; // Removed DisableMouseCapture
    terminal.show_cursor()?;

    if let Err(err) = result {
        println!("{:?}", err);
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    client: &XdrClient,
    incident_store: &mut IncidentStore,
) -> Result<()> {
    let mut poll_interval = interval(client.get_poll_interval());
    let mut should_exit = false;
    let mut last_poll_duration = client.get_poll_interval();
    
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
                        match key.code {
                            KeyCode::Char('q') => {
                                should_exit = true;
                            }
                            KeyCode::Esc | KeyCode::Backspace => {
                                if app.is_drill_down_mode() {
                                    app.exit_drill_down();
                                } else {
                                    should_exit = true;
                                }
                            }
                            KeyCode::Enter => {
                                if !app.is_drill_down_mode() && !app.filtered_incidents.is_empty() {
                                    app.enter_drill_down();
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
