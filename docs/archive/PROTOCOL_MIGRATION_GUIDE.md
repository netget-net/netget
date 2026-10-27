# Protocol Migration Guide: From Port-Based to Flexible Binding

This guide explains how to migrate a protocol from the old port-based binding system to the new flexible binding system that supports MAC addresses, interfaces, hostnames, and ports.

## Table of Contents

1. [Before You Start](#before-you-start)
2. [Migration Steps](#migration-steps)
3. [Port-Based Protocol Migration (TCP, HTTP, DNS, etc.)](#port-based-protocol-migration)
4. [Interface-Based Protocol Migration (ICMP, ARP, DataLink)](#interface-based-protocol-migration)
5. [Verification](#verification)
6. [Common Pitfalls](#common-pitfalls)
7. [After All Protocols Are Migrated](#after-all-protocols-are-migrated)

## Before You Start

### Prerequisites

- Phase 1 infrastructure must be in place:
  - `src/protocol/binding_defaults.rs` exists
  - `SpawnContext` has new optional fields
  - `OpenServer` action has new optional fields
  - `start_server_from_action` handles both paths

### Check Migration Status

Before migrating, check if the protocol is already migrated:

```rust
// In src/server/<protocol>/actions.rs
impl Server for MyProtocol {
    fn default_binding(&self) -> Option<BindingDefaults> {
        None  // ← Returns None = NOT MIGRATED
    }
}
```

If `default_binding()` returns `Some(...)`, the protocol is already migrated.

## Migration Steps

### Step 1: Identify Protocol Requirements

Determine what binding parameters your protocol needs:

| Protocol Type | Needs |
|---------------|-------|
| **Port-based** (TCP, HTTP, DNS) | `host` (default: "127.0.0.1"), `port` (default: 0) |
| **Interface-based** (ICMP, ARP) | `interface` (default: "lo") |
| **Layer 2** (ARP, DataLink) | `interface`, optionally `mac_address` |
| **Combined** (DHCP, WireGuard) | `interface`, `host`, `port` |

### Step 2: Implement `default_binding()`

Add `default_binding()` method to your protocol's `Server` implementation:

**File**: `src/server/<protocol>/actions.rs`

```rust
use crate::protocol::binding_defaults::BindingDefaults;

impl Server for MyProtocol {
    fn default_binding(&self) -> Option<BindingDefaults> {
        Some(BindingDefaults {
            mac_address: None,                          // Optional: layer 2 protocols
            interface: None,                            // Optional: raw socket protocols
            host: Some("127.0.0.1".to_string()),       // Required for port-based
            port: Some(0),                              // Required for port-based
        })
    }

    // ... rest of implementation
}
```

### Step 3: Update `spawn()` Method

Replace usage of `ctx.listen_addr` with the new helper methods:

**Before** (old way):
```rust
async fn spawn(&self, ctx: SpawnContext) -> Result<String> {
    #[allow(deprecated)]
    let socket_addr = ctx.listen_addr;  // ← OLD

    let actual_addr = MyServer::spawn_with_llm(
        socket_addr,
        ctx.llm_client,
        // ...
    ).await?;

    Ok(actual_addr.to_string())
}
```

**After** (new way):
```rust
async fn spawn(&self, ctx: SpawnContext) -> Result<String> {
    let socket_addr = ctx.socket_addr()                // ← NEW
        .context("MyProtocol requires host and port")?;

    let actual_addr = MyServer::spawn_with_llm(
        socket_addr,
        ctx.llm_client,
        // ...
    ).await?;

    Ok(actual_addr.to_string())
}
```

### Step 4: Update Protocol Prompt (Optional)

Update the protocol's prompt context to tell the LLM about the new fields:

**File**: `src/llm/prompt.rs` or protocol-specific prompt generation

**Before**:
```rust
"Use open_server with port=<number>"
```

**After**:
```rust
"Use open_server with:
  - port: Port number (defaults to 0 for dynamic assignment)
  - host: Bind address (defaults to '127.0.0.1')
  - interface: Specific network interface (optional)"
```

### Step 5: Test the Migration

1. **Run unit tests** (if any):
   ```bash
   ./cargo-isolated.sh test --no-default-features --features <protocol>
   ```

2. **Run E2E tests**:
   ```bash
   ./test-e2e.sh <protocol>
   ```

3. **Manual testing**:
   - Test with default binding (no parameters)
   - Test with custom binding (specific parameters)
   - Test with combined binding (interface + host + port)

## Port-Based Protocol Migration (TCP, HTTP, DNS, etc.)

### Example: Migrating TCP

**File**: `src/server/tcp/actions.rs`

#### 1. Implement `default_binding()`

```rust
impl Server for TcpProtocol {
    fn default_binding(&self) -> Option<BindingDefaults> {
        Some(BindingDefaults {
            mac_address: None,
            interface: None,
            host: Some("127.0.0.1".to_string()),  // Localhost by default
            port: Some(0),                         // Dynamic port by default
        })
    }
```

#### 2. Update `spawn()` Method

```rust
    async fn spawn(&self, ctx: SpawnContext) -> Result<String> {
        // Use new socket_addr() helper
        let socket_addr = ctx.socket_addr()
            .context("TCP requires host address and port")?;

        // Rest of implementation unchanged
        let actual_addr = crate::server::tcp::TcpServer::spawn_with_llm(
            socket_addr,
            ctx.llm_client,
            ctx.state,
            ctx.status_tx,
            ctx.server_id,
        ).await?;

        Ok(actual_addr.to_string())
    }
}
```

#### 3. Test TCP

```bash
./test-e2e.sh tcp
```

### Example: Migrating HTTP

Same pattern as TCP, but with HTTP-specific defaults:

```rust
impl Server for HttpProtocol {
    fn default_binding(&self) -> Option<BindingDefaults> {
        Some(BindingDefaults {
            mac_address: None,
            interface: None,
            host: Some("127.0.0.1".to_string()),
            port: Some(0),
        })
    }

    async fn spawn(&self, ctx: SpawnContext) -> Result<String> {
        let socket_addr = ctx.socket_addr()
            .context("HTTP requires host address and port")?;

        let actual_addr = crate::server::http::HttpServer::spawn_with_llm(
            socket_addr,
            ctx.llm_client,
            ctx.state,
            ctx.status_tx,
            ctx.server_id,
            ctx.startup_params,
        ).await?;

        Ok(actual_addr.to_string())
    }
}
```

## Interface-Based Protocol Migration (ICMP, ARP, DataLink)

### Example: Migrating ICMP

**File**: `src/server/icmp/actions.rs`

#### 1. Implement `default_binding()`

```rust
impl Server for IcmpProtocol {
    fn default_binding(&self) -> Option<BindingDefaults> {
        Some(BindingDefaults {
            mac_address: None,
            interface: Some("lo".to_string()),  // Loopback by default
            host: None,
            port: None,
        })
    }
```

#### 2. Update `spawn()` Method

```rust
    async fn spawn(&self, ctx: SpawnContext) -> Result<String> {
        // Extract interface (required for ICMP)
        let interface = ctx.interface()
            .context("ICMP requires network interface")?
            .to_string();

        // Spawn ICMP server
        crate::server::icmp::IcmpServer::spawn_with_llm(
            interface.clone(),
            ctx.llm_client,
            ctx.state,
            ctx.status_tx,
            ctx.server_id,
        ).await?;

        Ok(interface)
    }
}
```

#### 3. Test ICMP

```bash
./test-e2e.sh icmp
```

### Example: Migrating ARP (with Optional MAC)

**File**: `src/server/arp/actions.rs`

```rust
impl Server for ArpProtocol {
    fn default_binding(&self) -> Option<BindingDefaults> {
        Some(BindingDefaults {
            mac_address: None,                  // Optional: uses interface's actual MAC
            interface: Some("lo".to_string()),  // Required
            host: None,
            port: None,
        })
    }

    async fn spawn(&self, ctx: SpawnContext) -> Result<String> {
        // Extract interface (required)
        let interface = ctx.interface()
            .context("ARP requires network interface")?
            .to_string();

        // Extract MAC address (optional)
        let mac_address = ctx.mac_address.clone();

        // Spawn ARP server with optional MAC
        crate::server::arp::ArpServer::spawn_with_llm(
            interface.clone(),
            mac_address.clone(),
            ctx.llm_client,
            ctx.state,
            ctx.status_tx,
            ctx.server_id,
        ).await?;

        // Return interface with MAC if provided
        Ok(if let Some(mac) = mac_address {
            format!("{} (MAC: {})", interface, mac)
        } else {
            interface
        })
    }
}
```

## Verification

### Checklist for Migrated Protocol

- [ ] `default_binding()` returns `Some(BindingDefaults { ... })`
- [ ] `spawn()` uses `ctx.socket_addr()` or `ctx.interface()` (not `ctx.listen_addr`)
- [ ] Protocol compiles without warnings
- [ ] Unit tests pass (if any)
- [ ] E2E tests pass
- [ ] Manual testing works:
  - [ ] Default binding (no parameters)
  - [ ] Custom binding (specific parameters)
  - [ ] Combined binding (if applicable)

### Testing Commands

```bash
# Build protocol
./cargo-isolated.sh build --no-default-features --features <protocol>

# Run tests
./cargo-isolated.sh test --no-default-features --features <protocol>

# Run E2E test
./test-e2e.sh <protocol>

# Check for deprecation warnings
./cargo-isolated.sh build --no-default-features --features <protocol> 2>&1 | grep deprecated
```

### Verification Script

```bash
#!/bin/bash
# verify_migration.sh <protocol>

PROTOCOL=$1

echo "Verifying migration for $PROTOCOL..."

# Check if default_binding is implemented
if grep -q "fn default_binding.*Some" "src/server/$PROTOCOL/actions.rs"; then
    echo "✅ default_binding() implemented"
else
    echo "❌ default_binding() not implemented or returns None"
    exit 1
fi

# Check if spawn uses new methods
if grep -q "ctx.listen_addr" "src/server/$PROTOCOL/actions.rs"; then
    echo "⚠️  Warning: Still using ctx.listen_addr (should use ctx.socket_addr())"
fi

if grep -q "ctx.socket_addr()\|ctx.interface()" "src/server/$PROTOCOL/actions.rs"; then
    echo "✅ Using new context methods"
fi

# Build
echo "Building $PROTOCOL..."
./cargo-isolated.sh build --no-default-features --features "$PROTOCOL" > /tmp/build.log 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed, check /tmp/build.log"
    exit 1
fi

# Test
echo "Testing $PROTOCOL..."
./test-e2e.sh "$PROTOCOL" > /tmp/test.log 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Tests passed"
else
    echo "❌ Tests failed, check /tmp/test.log"
    exit 1
fi

echo "✅ Migration verified for $PROTOCOL"
```

## Common Pitfalls

### 1. Forgetting to Update `spawn()` Method

**Symptom**: Protocol still uses `ctx.listen_addr`

**Fix**: Replace with `ctx.socket_addr()` or `ctx.interface()`

### 2. Wrong Default Values

**Symptom**: Protocol doesn't work with defaults

**Fix**: Check your `default_binding()` returns appropriate defaults:
- Port-based: `host: Some("127.0.0.1"), port: Some(0)`
- Interface-based: `interface: Some("lo")`

### 3. Not Handling Optional Parameters

**Symptom**: Protocol crashes when optional parameter is None

**Fix**: Use `ctx.interface()?` or `ctx.mac_address()` (returns Result)

### 4. Deprecation Warnings

**Symptom**: Compiler warns about deprecated fields

**Fix**: Remove `#[allow(deprecated)]` and use new methods

### 5. Test Failures

**Symptom**: E2E tests fail after migration

**Fix**:
- Check if test mocks use old field names
- Update test expectations for new binding behavior
- Verify protocol defaults match test assumptions

## After All Protocols Are Migrated

Once ALL ~50 protocols have been migrated, you can perform the final cleanup (Phase N+1).

### Phase N+1: Cleanup (Breaking Changes - Requires v2.0)

This phase removes all deprecated fields and backwards compatibility code. **Only do this after confirming all protocols are migrated.**

#### 1. Verify All Protocols Migrated

```bash
# Check for protocols still using old path
./check_migration_status.sh

# Should output:
# ✅ All 50 protocols migrated
# No protocols return None from default_binding()
```

#### 2. Remove Deprecated Fields

**File**: `src/protocol/spawn_context.rs`

Remove:
```rust
#[deprecated(since = "1.x.0", note = "Use host/port fields instead")]
pub listen_addr: SocketAddr,
```

**File**: `src/state/server.rs`

Remove:
```rust
/// OLD FIELD: Port (for backwards compatibility)
pub port: u16,

pub local_addr: Option<SocketAddr>,
```

Keep only:
```rust
pub binding: ServerBinding,
```

#### 3. Update `ServerInstance` Helpers

Remove backwards-compatible helper methods that check old fields:

```rust
// REMOVE this:
pub fn get_port(&self) -> Option<u16> {
    if let Some(ref binding) = self.binding {
        binding.port
    } else {
        Some(self.port)  // ← OLD FIELD
    }
}

// KEEP this simplified version:
pub fn get_port(&self) -> Option<u16> {
    self.binding.port
}
```

#### 4. Remove Old Path in `start_server_from_action`

**File**: `src/cli/server_startup.rs`

Remove the old path entirely:

```rust
// REMOVE THIS ENTIRE BLOCK:
} else {
    // OLD PATH: Protocol hasn't been migrated
    let final_port = port.unwrap_or(0);
    (
        None,
        None,
        Some("127.0.0.1".to_string()),
        Some(final_port),
        false
    )
};
```

Simplify to:

```rust
// All protocols are migrated, always use new path
let defaults = protocol.default_binding();  // No longer returns Option
let (final_mac, final_interface, final_host, final_port) =
    defaults.apply(mac_address, interface, host, port);
```

#### 5. Make `default_binding()` Required

**File**: `src/llm/actions/protocol_trait.rs`

Change from:

```rust
fn default_binding(&self) -> Option<BindingDefaults> {
    None  // Default impl for unmigrated protocols
}
```

To:

```rust
fn default_binding(&self) -> BindingDefaults;  // ← Required, no default impl
```

#### 6. Remove Old SpawnContext Builder

Remove the old path that builds `SpawnContext` with `listen_addr`:

```rust
// REMOVE THIS:
} else {
    let listen_addr = format!("127.0.0.1:{}", actual_port.unwrap_or(0))
        .parse()
        .unwrap();

    SpawnContext {
        listen_addr,
        mac_address: None,
        interface: None,
        host: None,
        port: None,
        // ...
    }
};
```

#### 7. Update All Tests

Search for tests using old fields:

```bash
# Find tests using deprecated fields
grep -r "listen_addr" tests/
grep -r "\.port" tests/ | grep -v "binding.port"

# Update tests to use new binding system
```

#### 8. Update Documentation

- Mark old system as removed in `docs/archive/INTERFACE_PROTOCOL_ARCHITECTURE.md`
- Update `README.md` to only mention new system
- Update all protocol examples to use new binding
- Add migration notes to `CHANGELOG.md`

#### 9. Bump Major Version

In `Cargo.toml`:

```toml
[package]
name = "netget"
version = "2.0.0"  # ← Major version bump (breaking change)
```

#### 10. Final Verification

```bash
# Build all protocols
./cargo-isolated.sh build --all-features

# Run all tests
./cargo-isolated.sh test --all-features -- --test-threads=100

# Check for any remaining deprecation warnings
./cargo-isolated.sh build --all-features 2>&1 | grep -i deprecat

# Should output nothing (no deprecation warnings)
```

### Cleanup Checklist

- [ ] All protocols migrated (verified with script)
- [ ] `SpawnContext.listen_addr` removed
- [ ] `ServerInstance.port` and `local_addr` removed
- [ ] `ServerBinding` is now the only binding representation
- [ ] `default_binding()` is required (no default impl)
- [ ] Old path in `start_server_from_action` removed
- [ ] All tests updated
- [ ] Documentation updated
- [ ] Version bumped to 2.0.0
- [ ] All tests pass
- [ ] No deprecation warnings

## Migration Tracking

Use the table in `docs/archive/INTERFACE_PROTOCOL_ARCHITECTURE.md` to track migration status:

| Protocol | Status | Defaults | Notes |
|----------|--------|----------|-------|
| **ICMP** | ✅ Migrated | `{interface: "lo"}` | First to migrate |
| **TCP** | ⬜ Not Migrated | `{host: "127.0.0.1", port: 0}` | Proof of concept |
| **HTTP** | ⬜ Not Migrated | `{host: "127.0.0.1", port: 0}` | Common protocol |
| ... | ... | ... | ... |

Update this table as you migrate each protocol.

## Questions?

If you encounter issues during migration:

1. Check `docs/archive/INTERFACE_PROTOCOL_ARCHITECTURE.md` for design details
2. Look at migrated protocols (ICMP, TCP, HTTP) as examples
3. Verify Phase 1 infrastructure is in place
4. Run verification script to identify issues
5. Check compilation errors for hints

## Summary

### Quick Migration Steps

1. Implement `default_binding()` → return `Some(BindingDefaults { ... })`
2. Update `spawn()` → use `ctx.socket_addr()` or `ctx.interface()`
3. Test → run E2E tests to verify
4. Update table → mark protocol as migrated

### After All Migrations

1. Verify all protocols migrated
2. Remove deprecated fields
3. Simplify code paths
4. Update documentation
5. Bump to v2.0.0
6. Final testing

That's it! You're now ready to migrate protocols to the flexible binding system.
