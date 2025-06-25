# XDRTop Build Instructions

## System Requirements

- Rust 1.70 or later with Cargo
- OpenSSL development libraries
- pkg-config utility

## Installing Dependencies

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install pkg-config libssl-dev build-essential
```

### RHEL/CentOS/Fedora
```bash
# RHEL/CentOS
sudo yum install pkg-config openssl-devel gcc

# Fedora
sudo dnf install pkg-config openssl-devel gcc
```

### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install pkg-config openssl
```

### Alpine Linux
```bash
sudo apk add pkg-config openssl-dev build-base
```

## Building the Application

1. **Clone or copy the project files**
2. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. **Build the application**:
   ```bash
   cd xdrtop
   cargo build --release
   ```

## Troubleshooting OpenSSL Issues

If you encounter OpenSSL compilation errors, try these solutions:

### Option 1: Set Environment Variables
```bash
# Find OpenSSL installation
export OPENSSL_DIR=$(dirname $(dirname $(which openssl)))
export PKG_CONFIG_PATH="/usr/lib/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"

# Then build
cargo build --release
```

### Option 2: Use System-Specific Paths

**Ubuntu/Debian:**
```bash
export OPENSSL_DIR=/usr
export PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH"
cargo build --release
```

**macOS with Homebrew:**
```bash
export OPENSSL_DIR=/opt/homebrew/opt/openssl
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:$PKG_CONFIG_PATH"
cargo build --release
```

### Option 3: Vendored OpenSSL (Last Resort)
If system OpenSSL continues to cause issues, modify `Cargo.toml` to use vendored OpenSSL:

```toml
[dependencies]
openssl = { version = "0.10", features = ["vendored"] }
```

This will compile OpenSSL from source, avoiding system dependency issues.

## Running the Application

After successful compilation:

1. **Set up configuration**:
   ```bash
   ./target/release/xdrtop --init-config
   ```

2. **Start monitoring**:
   ```bash
   ./target/release/xdrtop
   ```

## Cross-Platform Notes

- **Windows**: Use WSL2 or install OpenSSL via vcpkg
- **ARM64**: Ensure you have ARM64-compatible OpenSSL libraries
- **Container**: Use multi-stage Docker builds with appropriate base images

## Support

If build issues persist, check:
1. `pkg-config --version` works
2. `pkg-config --libs --cflags openssl` returns valid paths
3. OpenSSL development headers are installed
4. Your system's package manager has up-to-date repositories