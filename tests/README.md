# NetGet End-to-End Tests

This directory contains comprehensive end-to-end tests for all NetGet protocols. Tests spawn the actual NetGet binary
and validate responses using real protocol client libraries.

## Test Files

| File                   | Tests | Client Library        | Requires Root |
|------------------------|-------|-----------------------|---------------|
| `e2e_tcp_test.rs`      | 3     | suppaftp, raw TCP     | No            |
| `e2e_http_test.rs`     | 6     | reqwest               | No            |
| `e2e_udp_test.rs`      | 1     | raw UDP               | No            |
| `e2e_dns_test.rs`      | 4     | hickory-net           | No            |
| `e2e_dhcp_test.rs`     | 3     | manual DHCP packets   | No            |
| `e2e_ntp_test.rs`      | 4     | rsntp                 | No            |
| `e2e_snmp_test.rs`     | 4     | snmp library, snmpget | No            |
| `e2e_ssh_test.rs`      | 4     | ssh2                  | No            |
| `e2e_irc_test.rs`      | 5     | raw IRC protocol      | No            |
| `e2e_datalink_test.rs` | 2     | pcap, arping          | **YES**       |

**Total:** 10 test files, 36 tests

## Running Tests

### Prerequisites

1. **Build the release binary** (required for all tests):
   ```bash
   ./cargo-isolated.sh build --release
   ```

2. **Start Ollama with a model**:
   ```bash
   ollama serve
   ollama pull qwen3-coder:30b  # or your preferred model
   ```

3. **Install protocol tools** (optional, for better coverage):
   ```bash
   # macOS
   brew install arping net-snmp

   # Linux
   sudo apt-get install arping snmp
   ```

### Running All Non-Privileged Tests

Most tests can run without elevated privileges:

```bash
./cargo-isolated.sh test --features <protocol>
```

### Running Privileged Tests (DataLink)

DataLink tests require raw packet capture access. There are several approaches:

#### Option 1: Run with sudo (macOS/Linux)

```bash
# Run only DataLink tests with sudo
sudo -E ./cargo-isolated.sh test --test e2e_datalink_test --features <protocol>

# The -E flag preserves environment variables (like PATH, CARGO_HOME)
```

**Pros:**

- Simple, works on all platforms
- Full packet capture access

**Cons:**

- Requires password entry
- Runs cargo with root (security risk)
- May create root-owned files in target/

#### Option 2: Wireshark pcap Group (macOS/Linux with Wireshark - EASIEST)

If you have Wireshark installed, you likely already have a special group for packet capture:

```bash
# Check if you're in the pcap/wireshark group
groups | grep -E 'wireshark|pcap'

# If not, add yourself (Linux)
sudo usermod -a -G wireshark $USER

# If not, add yourself (macOS - may be 'access_bpf')
sudo dseditgroup -o edit -a $USER -t user access_bpf

# Log out and back in for group changes to take effect
# Then run tests normally - no sudo needed!
./cargo-isolated.sh test --test e2e_datalink_test --features <protocol>
```

**Pros:**

- No sudo needed for test execution
- Group membership persists across reboots
- No need to re-apply after rebuilds
- Works on both macOS and Linux with Wireshark

**Cons:**

- Requires Wireshark to be installed
- Requires logout/login after adding to group (one-time)

#### Option 3: Linux Capabilities (Linux only)

Grant specific capabilities to the test binary without full root:

```bash
# Build the test binary first
./cargo-isolated.sh test --test e2e_datalink_test --features <protocol> --no-run

# Find the test binary
TEST_BIN=$(find target/debug/deps -name 'e2e_datalink_test-*' -type f -perm -111 | head -1)

# Grant packet capture capability
sudo setcap cap_net_raw,cap_net_admin=eip "$TEST_BIN"

# Now run without sudo
./cargo-isolated.sh test --test e2e_datalink_test --features <protocol>
```

**Pros:**

- No sudo needed for test execution
- Least privilege principle (only packet access, not full root)
- More secure than full sudo

**Cons:**

- Linux only
- Capability needs to be re-applied after each rebuild
- Requires initial sudo to set capabilities

#### Option 4: Automation Script (RECOMMENDED)

Create a helper script for privileged tests:

```bash
#!/bin/bash
# run_privileged_tests.sh

set -e

echo "Building test binary..."
./cargo-isolated.sh test --test e2e_datalink_test --features <protocol> --no-run

# Linux: Use capabilities
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Granting capabilities (Linux)..."
    TEST_BIN=$(find target/debug/deps -name 'e2e_datalink_test-*' -type f -perm -111 | head -1)
    sudo setcap cap_net_raw,cap_net_admin=eip "$TEST_BIN"

    echo "Running privileged tests without sudo..."
    ./cargo-isolated.sh test --test e2e_datalink_test --features <protocol>

# macOS: Use sudo
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Running with sudo (macOS)..."
    sudo -E ./cargo-isolated.sh test --test e2e_datalink_test --features <protocol>

else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "✓ Privileged tests completed"
```

Make it executable:

```bash
chmod +x run_privileged_tests.sh
./run_privileged_tests.sh
```

#### Option 5: Separate CI/CD Workflow

For CI/CD systems, create a separate workflow for privileged tests:

```yaml
# .github/workflows/e2e-privileged.yml
name: E2E Privileged Tests

on: [push, pull_request]

jobs:
  datalink-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build binary
        run: ./cargo-isolated.sh build --release

      - name: Start Ollama
        run: |
          curl https://ollama.ai/install.sh | sh
          ollama serve &
          sleep 5
          ollama pull qwen3-coder:30b

      - name: Run privileged tests
        run: |
          ./cargo-isolated.sh test --test e2e_datalink_test --features <protocol> --no-run
          TEST_BIN=$(find target/debug/deps -name 'e2e_datalink_test-*' -type f -perm -111 | head -1)
          sudo setcap cap_net_raw,cap_net_admin=eip "$TEST_BIN"
          ./cargo-isolated.sh test --test e2e_datalink_test --features <protocol>
```

### Running Individual Protocol Tests

Run tests for specific protocols:

```bash
# DNS tests
./cargo-isolated.sh test --test e2e_dns_test --features <protocol>

# HTTP tests
./cargo-isolated.sh test --test e2e_http_test --features <protocol>

# SSH tests
./cargo-isolated.sh test --test e2e_ssh_test --features <protocol>

# IRC tests
./cargo-isolated.sh test --test e2e_irc_test --features <protocol>

# etc.
```

### Running Specific Tests

Run individual test functions:

```bash
./cargo-isolated.sh test --test e2e_dns_test --features <protocol> test_dns_a_record_query
./cargo-isolated.sh test --test e2e_http_test --features <protocol> test_http_json_api
```

## Test Structure

All e2e tests follow the same pattern:

1. **PROMPT**: Define what the LLM should do
2. **Start Server**: Spawn NetGet binary with the prompt
3. **VALIDATION**: Use real protocol client library to test
4. **Cleanup**: Stop server

Example:

```rust
#[tokio::test]
async fn test_dns_a_record_query() -> E2EResult<()> {
    // PROMPT: Tell LLM to act as DNS server
    let port = 0; // the server owns its ephemeral socket until stopped
    let prompt = format!("listen on port {} via dns. Respond to A queries with 1.2.3.4", port);

    // Start server
    let server = helpers::start_netget_server(ServerConfig::new(prompt)).await?;

    // VALIDATION: Use the actual bound port reported by the server.
    let address = format!("127.0.0.1:{}", server.port).parse()?;
    let client = SyncClient::new(UdpClientConnection::new(address)?);
    let response = client.query(&name, DNSClass::IN, RecordType::A)?;
    assert!(!response.answers().is_empty());

    // Cleanup
    server.stop().await?;
    Ok(())
}
```

## Troubleshooting

### Tests timeout

- Ensure Ollama is running: `ollama serve`
- Check model is available: `ollama list`
- Increase timeout in test if LLM is slow

### Permission denied (DataLink tests)

- Use one of the privileged test approaches above
- Ensure you have admin/root access on the system

### Port already in use

- Tests use dynamic port allocation (port 0)
- If still failing, check for zombie processes: `pkill netget`

### Test fails with "binary not found"

- Build the release binary first: `./cargo-isolated.sh build --release`
- Check it exists: `ls -la target/release/netget`

### Capability persists after rebuild (Linux)

- Capabilities are removed when binary is modified
- Re-run `setcap` command after each `./cargo-isolated.sh build`
- Use the automation script to handle this automatically

## Best Practices

1. **Always build release binary first** - Tests spawn the actual binary
2. **Use debug logging for failing tests** - Add `.with_log_level("debug")` to ServerConfig
3. **Run non-privileged tests frequently** - They're safe and fast
4. **Run privileged tests separately** - Use the automation script or CI/CD
5. **Don't run cargo with sudo unless necessary** - Prefer capabilities on Linux
6. **Clean up zombie processes** - Kill any hanging netget processes between test runs

## Contributing

When adding new protocol tests:

1. Create a new `e2e_<protocol>_test.rs` file
2. Use a proper protocol client library (not raw bytes)
3. Follow the existing test pattern (prompt → spawn → validate → cleanup)
4. Add at least 3-4 tests covering different protocol features
5. Document if the test requires special privileges
6. Update this README with the new test file
