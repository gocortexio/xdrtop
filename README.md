<div align="center">
  <img src="assets/xdrtop-logo.png" alt="XDRTop Logo" width="600"/>
</div>

# XDRTop

Terminal-based monitoring tool for Cortex XSIAM/CLOUD and XDR from GoCortex.io

A Rust CLI application providing real-time, interactive case tracking with an htop-style interface. XDRTop connects to the Cortex Platform Cases API to display security cases with filtering, drill-down issue details, and MITRE ATT&CK framework integration.

## Overview

XDRTop enables security teams to monitor Cortex Platform cases directly from the terminal without browser access. It fetches all cases using intelligent pagination, caches results for performance, and provides keyboard-driven navigation for efficient case triage.

### Features

- Interactive terminal interface with real-time updates
- Complete case coverage via paginated API fetching
- Two-minute smart caching to reduce API load
- Severity and status filtering with keyboard shortcuts
- Case drill-down showing issue details and MITRE ATT&CK data
- Domain-based filtering (Security, Posture)
- Cross-platform support (Linux, macOS, Windows)

## Installation

### Prerequisites

- Rust 1.70 or later
- Cortex Platform API credentials (API Key ID and Secret)
- Network access to your Cortex Platform tenant

### Building from Source

```bash
git clone https://github.com/gocortexio/xdrtop.git
cd xdrtop
cargo build --release
```

The binary will be available at `target/release/xdrtop`

## Configuration

Run the following command to configure API credentials:

```bash
./xdrtop --init-config
```

You will be prompted to enter:
- API Key ID: Your Cortex Platform API key identifier
- API Key Secret: Your Cortex Platform API secret key
- Tenant URL: Your Cortex Platform tenant URL (e.g., https://api-tenant.xdr.au.paloaltonetworks.com)

Credentials are stored in a platform-specific location:
- Linux/macOS: ~/.xdrtop/config.json
- Windows: %USERPROFILE%\.xdrtop\config.json

## Usage

### Starting XDRTop

```bash
./xdrtop
```

### Command Line Options

| Option | Description |
|--------|-------------|
| --init-config | Configure API credentials |
| --debug | Enable debug logging to debug_output.log |
| --help | Display help information |
| --version | Show version information |

### Keyboard Controls

| Key | Action |
|-----|--------|
| Up/Down | Navigate through cases |
| Enter | View case details and issues |
| Esc | Return to main view |
| q | Quit application |
| 1-4 | Filter by severity (1=Critical, 2=High, 3=Medium, 4=Low) |
| s | Cycle through status filters |
| d | Cycle through domain filters |
| c | Clear all filters |

### Colour Coding

| Severity | Colour |
|----------|--------|
| Critical | Red |
| High | Light Red |
| Medium | Yellow |
| Low | Green |

## API Integration

XDRTop uses the Cortex XDR v1 API:

| Endpoint | Purpose |
|----------|---------|
| /public_api/v1/case/search | Fetch cases with pagination |
| /public_api/v1/issue/search | Fetch issue details for drill-down |

The application polls every two minutes with automatic rate limiting and exponential backoff for error recovery.

## Troubleshooting

### Configuration Not Found

```
Error: Configuration file not found
```

Run `./xdrtop --init-config` to set up credentials.

### API Connection Issues

```
Error: builder error: relative URL without a base
```

Verify the tenant URL includes the protocol (https://) and is correctly formatted.

### Debug Mode

For detailed logging:

```bash
./xdrtop --debug
```

Debug output is written to debug_output.log in the current directory.

## Contact and Support

For documentation, updates, and support, visit GoCortex.io (https://gocortex.io).

Developed by Simon Sigre at GoCortex.io.

---

Version: 2.0.3 | Licence: MIT | Platform: Linux, macOS, Windows
