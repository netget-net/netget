# NetGet System Dependencies for macOS

This document describes which NetGet protocols require external system dependencies on macOS and how to install them.

## Overview

Most NetGet protocols are implemented in pure Rust and have no system dependencies. However, some protocols require native system libraries for proper functionality:

### Protocols with System Dependencies

| Protocol | System Requirement | Crate | Installation | Notes |
|----------|------------------|-------|--------------|-------|
| **WireGuard Client** | TUN Interface | defguard_wireguard_rs | Built-in (userspace) | Uses wireguard-go userspace implementation |
| **OpenVPN** | TUN/TAP Interface | tun (planned) | Manual setup required | Not yet fully implemented |
| **PostgreSQL Client** | libpq | pgwire | Homebrew | Only if connecting to PostgreSQL servers |
| **MySQL Client** | libmysqlclient | opensrv-mysql | Homebrew | Only if using MySQL protocol |
| **Git** | libgit2 | git2 | Homebrew | For git:// protocol support |

### Pure Rust Protocols (No System Dependencies)

Most protocols are implemented in pure Rust and require **no system dependencies**:

- **TCP, UDP** - Core OS socket APIs (always available)
- **HTTP/1.1, HTTP/2, HTTP/3** - Pure Rust implementation
- **DNS** - Pure Rust via hickory
- **TLS/SSL** - Pure Rust via rustls (no OpenSSL needed)
- **DHCP, BOOTP, NTP, ARP, IGMP** - Pure Rust network protocols
- **SSH** - Pure Rust via russh
- **IRC, XMPP, SMTP, IMAP** - Pure Rust implementations
- **Redis, Cassandra, Elasticsearch, etcd** - Pure Rust client libraries
- **gRPC** - Pure Rust with tonic
- **WebRTC** - Pure Rust implementation
- **Bitcoin, Torrent, Tor** - Pure Rust implementations
- And 30+ others...

## Detailed Installation Guide

### 1. WireGuard Client (Recommended for testing VPN functionality)

**macOS Implementation**: Uses userspace `wireguard-go` implementation - **no system dependencies required**.

WireGuard on macOS:
- Uses userspace TUN interface (no kernel module needed)
- Works on both Intel and Apple Silicon (M1/M2/M3) Macs
- No special installation required beyond Rust

**Verify WireGuard works**:
```bash
# Just build with the wireguard feature - no additional setup needed
cargo build --no-default-features --features wireguard
```

### 2. PostgreSQL Client (Optional - only if using PostgreSQL protocol)

**When to install**: Only needed if you want to connect to PostgreSQL servers as a client.

**Install PostgreSQL client libraries**:
```bash
# Using Homebrew
brew install postgresql

# Verify installation
pg_config --version

# Set PostgreSQL client lib path if needed
export PKG_CONFIG_PATH="/opt/homebrew/opt/postgresql/lib/pkgconfig"
```

### 3. MySQL Client (Optional - only if using MySQL protocol)

**When to install**: Only needed if you want to connect to MySQL servers as a client.

**Install MySQL client libraries**:
```bash
# Using Homebrew
brew install mysql-client

# Verify installation
mysql_config --version

# Add to PATH if needed
export PATH="/opt/homebrew/opt/mysql-client/bin:$PATH"
```

### 4. Apache Kafka — **no system dependency**

The `kafka` feature builds the broker *and* the client from `kafka-protocol`, which is pure
Rust. **librdkafka is not required and is no longer a dependency**: `rdkafka` was removed
because it aborted in malloc, and the optional feature it left behind gated the Kafka client
out of every `--features kafka` build.

Only install a broker if you want to test NetGet's *client* against a real one:

```bash
brew install kafka   # optional, for interoperability testing only
```

### 5. Git Support (Optional - if using Git protocol)

**When to install**: Only needed for git:// protocol support.

**Install libgit2**:
```bash
# Using Homebrew
brew install libgit2

# Verify installation
pkg-config --modversion libgit2

# Set PKG_CONFIG_PATH if needed
export PKG_CONFIG_PATH="/opt/homebrew/opt/libgit2/lib/pkgconfig"
```

## Building with Different Feature Combinations

### Minimal Build (Pure Rust Only)
```bash
# Build with core protocols only - NO system dependencies
./cargo-isolated.sh build --no-default-features --features tcp,http,dns,ssh
```

### Recommended Build for Testing
```bash
# Includes WireGuard (no deps), basic protocols
./cargo-isolated.sh build --no-default-features --features tcp,http,dns,wireguard
```

### Full Feature Build (with system libraries)
```bash
# First install system dependencies:
brew install postgresql git libgit2

# Then build with all features:
./cargo-isolated.sh build --all-features
```

## Testing System Dependencies

### Verify PostgreSQL Setup
```bash
# Check if PostgreSQL is available
psql --version

# If error "psql: command not found", add to PATH:
export PATH="/opt/homebrew/opt/postgresql/bin:$PATH"

# Test connection (requires running PostgreSQL server)
psql -h localhost -U postgres -d postgres -c "SELECT version();"
```

### Verify MySQL Setup
```bash
# Check MySQL client
mysql --version

# Test connection (requires running MySQL server)
mysql -h localhost -u root -e "SELECT @@version;"
```

### Verify Kafka Setup

Nothing to verify — the Kafka broker and client are pure Rust. If you installed a real broker
to test interoperability against:

```bash
$KAFKA_HOME/bin/kafka-console-producer.sh --broker-list localhost:9092 --topic test
```

## Troubleshooting

### "ld: symbol not found" for PostgreSQL
**Solution**: Set `PKG_CONFIG_PATH`:
```bash
export PKG_CONFIG_PATH="/opt/homebrew/opt/postgresql/lib/pkgconfig"
cargo build --no-default-features --features postgresql
```

### "Library not found" for MySQL
**Solution**: Add MySQL to PATH:
```bash
export PATH="/opt/homebrew/opt/mysql-client/bin:$PATH"
export PKG_CONFIG_PATH="/opt/homebrew/opt/mysql-client/lib/pkgconfig"
cargo build --no-default-features --features mysql
```

### WireGuard "Permission denied" on macOS
**Note**: WireGuard on macOS uses userspace (no elevated privileges needed), unlike Linux which requires root.

## Environment Variables

### Recommended Setup for All Protocols
```bash
# Add this to ~/.bashrc or ~/.zshrc for permanent setup:

# PostgreSQL (if installed)
if [ -d "/opt/homebrew/opt/postgresql" ]; then
  export PKG_CONFIG_PATH="/opt/homebrew/opt/postgresql/lib/pkgconfig:$PKG_CONFIG_PATH"
  export PATH="/opt/homebrew/opt/postgresql/bin:$PATH"
fi

# MySQL (if installed)
if [ -d "/opt/homebrew/opt/mysql-client" ]; then
  export PKG_CONFIG_PATH="/opt/homebrew/opt/mysql-client/lib/pkgconfig:$PKG_CONFIG_PATH"
  export PATH="/opt/homebrew/opt/mysql-client/bin:$PATH"
fi

# libgit2 (if installed)
if [ -d "/opt/homebrew/opt/libgit2" ]; then
  export PKG_CONFIG_PATH="/opt/homebrew/opt/libgit2/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

```

## macOS-Specific Notes

### Apple Silicon (M1/M2/M3) Macs
- All recommended packages are available via Homebrew for Apple Silicon
- Homebrew paths differ: `/opt/homebrew` instead of `/usr/local`
- All protocols work identically on Apple Silicon

### Intel Macs
- Same Homebrew paths apply
- All tested and working

### Homebrew Installation
If you don't have Homebrew installed:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## See Also

- Individual protocol documentation: `src/server/<protocol>/CLAUDE.md`
- Build system documentation: `README.md`
- Feature configuration: `Cargo.toml`

