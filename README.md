# XDRTop

A high-performance Rust CLI monitoring tool for Cortex XDR, delivering real-time, interactive case tracking with advanced terminal-based visualisation and comprehensive filtering capabilities.

## Features

### Core Monitoring
- **Real-time Case Monitoring**: Polls Cortex XDR API every 30 seconds for the latest case data
- **Interactive Terminal UI**: htop-style interface with keyboard navigation and drill-down capabilities
- **Advanced Filtering**: Filter cases by severity levels and status with keyboard shortcuts
- **Detailed Case View**: Press Enter to view comprehensive case details including associated issues
- **Rate Limiting**: Built-in exponential backoff to handle API rate limits gracefully
- **Secure Configuration**: Stores encrypted API credentials in `~/.xdrtop/config.json`

### User Interface
- **Responsive Design**: Modern terminal interface with colour-coded severity and status indicators
- **Real-time Statistics**: Live counts of cases by severity and status
- **Filter Status Display**: Visual indication of active filters and case counts
- **Status Tracking**: Real-time status updates and error handling with visual feedback
- **Intuitive Controls**: Comprehensive keyboard shortcuts for all functionality

### Data Management
- **Efficient Data Processing**: Optimised case handling with minimal memory footprint
- **Australian English**: All terminology uses Australian spelling and conventions
- **Smart Filtering**: Cases filtered by "Critical/High/Medium/Low" severity and various status types
- **Issue Management**: Cases contain "Issues" (not "Alerts") with detailed drill-down information

## Key Technologies

- **Rust**: High-performance systems programming language for optimal terminal performance
- **Tokio**: Async runtime for concurrent operations and non-blocking API calls
- **Ratatui**: Modern terminal user interface framework with rich widgets
- **Serde**: JSON serialisation/deserialisation for API data handling
- **Reqwest**: HTTP client with TLS support for secure API communication
- **Chrono**: Date and time handling with timezone support
- **Crossterm**: Cross-platform terminal manipulation

## Installation

### Prerequisites

- Rust 1.70 or later
- Cortex XDR API credentials (API Key ID and Secret)
- Network access to your Cortex XDR tenant

### Building from Source

```bash
git clone <repository-url>
cd xdrtop
cargo build --release
```

The binary will be available at `target/release/xdrtop`

### Quick Build

```bash
cargo run
```

## Configuration

### Initial Setup

Run the following command to set up your API credentials:

```bash
./xdrtop --init-config
```

You'll be prompted to enter:
- **API Key ID**: Your Cortex XDR API key identifier
- **API Key Secret**: Your Cortex XDR API secret key
- **Tenant URL**: Your Cortex XDR tenant URL (e.g., `https://api-your-tenant.xdr.us.paloaltonetworks.com`)

### Configuration File

Credentials are stored securely in `~/.xdrtop/config.json` with the following structure:

```json
{
  "api_key_id": "your-api-key-id",
  "api_key_secret": "your-api-key-secret",
  "tenant_url": "https://api-your-tenant.xdr.us.paloaltonetworks.com"
}
```

## Usage

### Basic Operation

```bash
./xdrtop
```

### Command Line Options

- `--init-config`: Initialise API configuration
- `--help`: Display help information
- `--version`: Show version information

### Interface Navigation

#### Basic Controls
- **↑/↓ Arrow Keys**: Navigate through cases
- **Enter**: View detailed case information and associated issues
- **Esc/Backspace**: Exit drill-down mode or quit application
- **q**: Quit application

#### Filtering Controls
- **1**: Filter by Critical severity cases
- **2**: Filter by High severity cases
- **3**: Filter by Medium severity cases
- **4**: Filter by Low severity cases
- **s**: Cycle through status filters (New → Under Investigation → Resolved → Closed → Clear)
- **c**: Clear all active filters

### Main Interface

The interface consists of several panels:

1. **Header**: Application title and case statistics (shows filtered/total counts when filters active)
2. **Cases Table**: List of cases with key information and colour coding
3. **Sidebar**: 
   - **Severity Breakdown**: Live counts of Critical, High, Medium, Low cases
   - **Status Summary**: Counts by case status with colour indicators
   - **Filters & Controls**: Active filter display and keyboard shortcut reference
4. **Status Bar**: Connection status and comprehensive keyboard shortcuts

### Cases Table Columns

- **ID**: Unique case identifier (truncated for display)
- **Severity**: Case severity level with colour coding
- **Status**: Current case status with colour coding
- **Description**: Brief case description
- **Issues**: Number of associated issues (formerly alerts)
- **Created**: Case creation timestamp

### Drill-Down Mode

Press **Enter** on any case to view detailed information:

- **Complete Case Metadata**: Full case details including ID, severity, status
- **Associated Issues**: Detailed list of security issues with:
  - Issue names and descriptions
  - Severity levels and categories
  - Source systems and affected hosts
  - Detection timestamps
- **Case Timeline**: Creation and modification timestamps
- **Assignment Information**: Assigned users and investigation status

### Filtering System

XDRTop provides comprehensive filtering capabilities:

#### Severity Filtering
- **Critical Cases**: Press `1` to show only critical severity cases
- **High Severity**: Press `2` to show only high severity cases  
- **Medium Severity**: Press `3` to show only medium severity cases
- **Low Severity**: Press `4` to show only low severity cases

#### Status Filtering
- **Cycle Statuses**: Press `s` to cycle through status filters:
  - New cases
  - Under Investigation
  - Resolved cases
  - Closed cases
  - Clear filter (show all)

#### Filter Management
- **Clear All**: Press `c` to remove all active filters
- **Visual Indicators**: Active filters shown in sidebar with case counts
- **Dynamic Counts**: Header shows filtered/total case counts when filters are active

## API Integration

### Endpoints Used

- `POST /public_api/v1/incidents/get_incidents/`: Fetches case data from Cortex XDR
- Standard Cortex XDR authentication headers and request format
- JSON request/response handling with proper error management

### Rate Limiting

XDRTop implements intelligent rate limiting:

- **Base Interval**: 30-second polling cycle
- **Exponential Backoff**: Automatic retry with increasing delays on rate limit hits
- **Graceful Degradation**: Continues operation during temporary API issues
- **Error Recovery**: Smart reconnection logic with visual status updates

### Data Processing

- **Real-time Updates**: Automatically refreshes case data every 30 seconds
- **Efficient Caching**: Minimises API calls while maintaining data freshness
- **Error Resilience**: Continues operation during temporary API unavailability
- **Data Transformation**: Converts API response to optimised internal data structures

## Colour Coding

### Severity Levels
- **Critical**: Red text (bold) - highest priority cases
- **High**: Light Red text - significant security issues
- **Medium**: Yellow text - moderate priority cases
- **Low**: Green text - informational or low-risk cases

### Status Types
- **New**: Light Blue text - newly detected cases awaiting review
- **Under Investigation**: Yellow text - cases being actively investigated
- **Resolved**: Green text - cases with identified solutions
- **Closed**: Grey text - completed cases

## Performance

- **Memory Efficient**: Minimal memory footprint with efficient data structures
- **CPU Optimised**: Async operations prevent UI blocking and maintain responsiveness
- **Network Efficient**: Intelligent polling reduces bandwidth usage
- **Terminal Responsive**: Smooth interface updates with optimised rendering
- **Filter Performance**: Instant filtering with no API calls required

## Security Considerations

- **Credential Storage**: API credentials stored in user home directory with restricted permissions
- **Network Security**: All API communications use TLS encryption
- **No Data Persistence**: Case data is not stored locally beyond active session
- **Memory Safety**: Rust's memory safety prevents common security vulnerabilities
- **Input Validation**: All API responses validated before processing

## Troubleshooting

### Common Issues

1. **Configuration Errors**
   ```
   Error: Configuration file not found. Run with --init-config to set up credentials.
   ```
   **Solution**: Run `./xdrtop --init-config` to set up credentials

2. **API Connection Issues**
   ```
   Error: builder error: relative URL without a base
   ```
   **Solution**: Verify tenant URL includes protocol (https://) and is correctly formatted

3. **Authentication Failures**
   ```
   Error: Authentication failed
   ```
   **Solution**: Verify API key ID and secret are correct and have proper permissions

4. **Rate Limiting**
   ```
   Warning: Rate limit exceeded, backing off...
   ```
   **Solution**: XDRTop automatically handles this with exponential backoff

5. **Network Connectivity**
   ```
   Error: Failed to connect to API
   ```
   **Solution**: Check network connectivity and firewall settings

### Debug Mode

For detailed logging, set the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug ./xdrtop
```

Available log levels: `error`, `warn`, `info`, `debug`, `trace`

## Development

### Building for Development

```bash
cargo run
```

### Running Tests

```bash
cargo test
```

### Development Dependencies

```bash
cargo build
```

### Code Structure

- **`src/main.rs`**: Application entry point, event loop, and keyboard handling
- **`src/ui.rs`**: Terminal interface implementation with filtering and drill-down
- **`src/api.rs`**: Cortex XDR API client with rate limiting and error handling
- **`src/incidents.rs`**: Case data structures and processing logic
- **`src/config.rs`**: Configuration management and credential storage

### Adding Features

1. **New Filters**: Add filter logic to `apply_filters()` method in `ui.rs`
2. **UI Components**: Extend drawing functions in `ui.rs` for new interface elements
3. **API Extensions**: Modify `api.rs` for additional API endpoints
4. **Data Fields**: Update structures in `incidents.rs` for new case attributes

## Architecture

### Event-Driven Design
- **Async Event Loop**: Non-blocking keyboard input and API calls
- **State Management**: Centralised application state with filtered views
- **Reactive UI**: Interface updates based on state changes and user input

### Data Flow
1. **API Polling**: Regular case data fetching from Cortex XDR
2. **Data Processing**: Transform API response to internal structures
3. **Filter Application**: Apply user-selected filters to case list
4. **UI Rendering**: Display filtered cases with real-time statistics
5. **User Interaction**: Handle keyboard input for navigation and filtering

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following Rust best practices
4. Add tests for new functionality
5. Ensure all tests pass (`cargo test`)
6. Update documentation as needed
7. Submit a pull request with detailed description

### Code Standards
- **Rust Formatting**: Use `cargo fmt` for consistent formatting
- **Linting**: Run `cargo clippy` to catch common issues
- **Testing**: Include unit tests for new functionality
- **Documentation**: Add rustdoc comments for public APIs

## Licence

This project is licensed under the MIT Licence - see the LICENCE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review existing GitHub issues
3. Create a new issue with detailed information including:
   - Operating system and terminal type
   - Rust version (`rustc --version`)
   - Error messages and logs
   - Steps to reproduce the issue

## Acknowledgements

- **Palo Alto Networks**: For the Cortex XDR API
- **Rust Community**: For excellent crates and documentation
- **Ratatui Project**: For the powerful terminal UI framework

## Version History

- **v0.1.0**: Initial release with core monitoring functionality, filtering system, and drill-down capabilities