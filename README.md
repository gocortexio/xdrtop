# XDRTop

A high-performance Rust CLI monitoring tool for Cortex XDR, delivering real-time, interactive case tracking with advanced terminal-based visualisation and comprehensive filtering capabilities.

## Features

### Core Features
- **Interactive Terminal**: htop-style interface with keyboard navigation
- **Real-time Monitoring**: Automatic polling with live case updates
- **Comprehensive Filtering**: Filter by severity (Critical/High/Medium/Low) and status
- **Detailed Case View**: Drill-down to see complete case information and associated alerts
- **Secure Configuration**: Encrypted API credentials stored locally

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

#### Windows Requirements
- **Microsoft Visual C++ Redistributable**: Required to resolve vcruntime140.dll errors
  - Download from: https://aka.ms/vs/17/release/vc_redist.x64.exe
  - Install both x64 and x86 versions if unsure about your system architecture
- **Windows 10/11**: Recommended for best compatibility

### Building from Source

```bash
git clone https://github.com/your-org/xdrtop.git
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
- **Tenant URL**: Your Cortex XDR tenant URL (e.g., `https://api-your-tenant.xdr.au.paloaltonetworks.com`)

### Configuration File

Credentials are stored securely in a platform-specific location:
- **Windows**: `%USERPROFILE%\.xdrtop\config.json` (e.g., `C:\Users\username\.xdrtop\config.json`)
- **Linux/macOS**: `~/.xdrtop/config.json`

The configuration file has the following structure:

```json
{
  "api_key_id": "your-api-key-id",
  "api_key_secret": "your-api-key-secret",
  "tenant_url": "https://api-your-tenant.xdr.au.paloaltonetworks.com"
}
```

## Usage

### Basic Operation

```bash
./xdrtop
```

### Command Line Options

- `--init-config`: Initialise API configuration
- `--debug`: Enable debug logging to debug_output.log file
- `--help`: Display help information
- `--version`: Show version information

### Usage

**Basic Navigation:**
- `↑/↓` - Navigate through cases
- `Enter` - View detailed case information
- `Esc` - Return to main view
- `q` - Quit application

**Filtering:**
- `1-4` - Filter by severity (Critical/High/Medium/Low)
- `s` - Cycle through status filters
- `c` - Clear all filters

## API Integration

XDRTop uses two Cortex XDR API endpoints:

- **Main Cases**: `POST /public_api/v1/incidents/get_incidents/` - Fetches case list
- **Case Details**: `POST /public_api/v1/incidents/get_incident_extra_data/` - Fetches detailed case information and alerts

The application polls every 30 seconds with automatic rate limiting and error recovery.

## Colour Coding

- **Critical**: Red (highest priority)
- **High**: Light Red
- **Medium**: Yellow
- **Low**: Green

## Security

- API credentials stored securely in user home directory
- All communications use TLS encryption
- No local data persistence beyond active session

## Troubleshooting

### Common Issues

1. **Configuration Errors**
   ```
   Error: Configuration file not found. Run with --init-config to set up credentials.
   ```
   **Solution**: Run `./xdrtop --init-config` to set up credentials

2. **Windows vcruntime140.dll Error**
   ```
   Error: The code execution cannot proceed because vcruntime140.dll was not found
   ```
   **Solution**: Install Microsoft Visual C++ Redistributable:
   - Download: https://aka.ms/vs/17/release/vc_redist.x64.exe
   - Run installer as administrator
   - Restart terminal/command prompt after installation

3. **Windows Application Stability**
   If the Windows version starts in case details mode or crashes on Escape:
   - This issue has been fixed in v1.0.12+ (current: v1.0.24)
   - The application now properly initialises in main table view
   - Escape key handling is more robust and won't cause crashes

3. **API Connection Issues**
   ```
   Error: builder error: relative URL without a base
   ```
   **Solution**: Verify tenant URL includes protocol (https://) and is correctly formatted

4. **Authentication Failures**
   ```
   Error: Authentication failed
   ```
   **Solution**: Verify API key ID and secret are correct and have proper permissions

5. **Rate Limiting**
   ```
   Warning: Rate limit exceeded, backing off...
   ```
   **Solution**: XDRTop automatically handles this with exponential backoff

6. **Network Connectivity**
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

### Version Information

To check the current version:

```bash
./xdrtop --version
```

Current release: **v1.0.32** with integrated MITRE ATT&CK framework support.

## Development

```bash
git clone https://github.com/your-org/xdrtop.git
cd xdrtop
cargo build --release
```

Built with Rust for high performance and cross-platform compatibility.

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

