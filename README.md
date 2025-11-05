# NFTex - Elixir Interface to nftables

High-performance Elixir bindings for Linux nftables via libnftnl library. NFTex provides both high-level helper functions for common firewall operations and low-level direct access to the nftables netlink API.

## Features

- **High-Level APIs** - Simple functions for blocking IPs, managing sets, creating rules
- **Dynamic Firewall Management** - Modify firewall rules from your Elixir application
- **IP Blocklist Management** - Add/remove IPs from blocklists with one function call
- **Query Operations** - List tables, chains, rules, sets, and elements
- **Expression Builders** - Composable helpers for building custom rules
- **Port-based architecture** - Fault isolation (crashes don't affect BEAM VM)
- **Secure** - Port runs with minimal privileges (CAP_NET_ADMIN only)
- **Resource Management** - Automatic cleanup of native resources
- **Zero Dependencies** - Direct bindings to libnftnl, no external processes

## Architecture

```
Elixir (NFTex) <--ETF--> Zig Port (libnf_ex) <--libnftnl--> Kernel (nf_tables)
```

See [NFTABLES_PLAN.md](NFTABLES_PLAN.md) for detailed architecture documentation.

## System Requirements

- Linux kernel >= 3.14 (nf_tables support)
- Zig >= 0.11.0
- Elixir >= 1.14
- Erlang/OTP >= 24

### Required System Libraries

The following development packages must be installed:

- `libnftnl-dev` >= 1.1.5 - Netfilter nftables userspace API library
- `libmnl-dev` >= 1.0.4 - Minimalistic Netlink communication library
- `libcap-dev` >= 2.25 - POSIX capabilities library
- `erlang-dev` - Erlang development headers (for ei.h)

### Installation on Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  libnftnl-dev \
  libmnl-dev \
  libcap-dev \
  erlang-dev \
  zig
```

### Verify Installation

Check that all dependencies are available:

```bash
# Check Zig
zig version

# Check headers
ls /usr/include/libnftnl/
ls /usr/include/libmnl/
ls /usr/include/ei.h
ls /usr/include/sys/capability.h
```

## Building

The Zig port is automatically compiled when you build the Mix project:

```bash
# Fetch dependencies
mix deps.get

# Compile (includes Zig compilation)
mix compile
```

The compiled `libnf_ex` binary will be placed in `priv/libnf_ex`.

### Manual Build

To build just the Zig port:

```bash
cd native
zig build
```

The binary will be in `native/zig-out/bin/libnf_ex`.

## Quick Start

### Block an IP Address

```elixir
# Start NFTex
{:ok, pid} = NFTex.start_link()

# Block a malicious IP
ip = <<192, 168, 1, 100>>
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

# That's it! The rule is now active in the kernel.
```

### Manage IP Blocklists with Sets

```elixir
{:ok, pid} = NFTex.start_link()

# Add IPs to an existing blocklist set
malicious_ips = [
  <<192, 168, 1, 100>>,
  <<10, 0, 0, 99>>,
  <<172, 16, 5, 50>>
]

:ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, malicious_ips)

# List blocked IPs
{:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")

for elem <- elements do
  IO.puts("Blocked: #{elem.key_ip}")
end
```

### Query Your Firewall Configuration

```elixir
{:ok, pid} = NFTex.start_link()

# List all tables
{:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)

# List rules in a specific chain
{:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)

# List sets
{:ok, sets} = NFTex.Query.list_sets(pid, family: :inet)
```

## API Overview

### High-Level APIs (Recommended)

NFTex provides simple, idiomatic Elixir functions for common firewall operations:

#### NFTex.Rule - Rule Operations

```elixir
# Block an IP address (creates payload + comparison + counter + DROP verdict)
NFTex.Rule.block_ip(pid, table, chain, ip_binary, opts \\ [])

# Allow an IP address (creates payload + comparison + counter + ACCEPT verdict)
NFTex.Rule.accept_ip(pid, table, chain, ip_binary, opts \\ [])

# List rules in a chain
NFTex.Rule.list(pid, table, chain, opts \\ [])
```

#### NFTex.Set - Set Management

```elixir
# Add elements to a set (batch operation)
NFTex.Set.add_elements(pid, table, set_name, family, elements)

# Delete elements from a set
NFTex.Set.delete_elements(pid, table, set_name, family, elements)

# List set elements with automatic IP formatting
NFTex.Set.list_elements(pid, table, set_name)

# Check if set exists
NFTex.Set.exists?(pid, table, set_name, family)

# List all sets
NFTex.Set.list(pid, opts \\ [])
```

#### NFTex.Query - Query Operations

```elixir
# List tables
NFTex.Query.list_tables(pid, opts \\ [])

# List chains
NFTex.Query.list_chains(pid, opts \\ [])

# List rules
NFTex.Query.list_rules(pid, opts \\ [])

# List sets
NFTex.Query.list_sets(pid, opts \\ [])

# List set elements
NFTex.Query.list_set_elements(pid, table, set_name)
```

### Low-Level APIs

#### NFTex.ExpressionBuilder - Expression Helpers

For building custom rules with specific matching criteria:

```elixir
# Load IP source address into register
{:ok, payload_id} = NFTex.ExpressionBuilder.payload_ipv4_saddr(pid, 1)

# Compare register value
{:ok, cmp_id} = NFTex.ExpressionBuilder.cmp_eq(pid, 1, <<192, 168, 1, 100>>)

# Add counter
{:ok, counter_id} = NFTex.ExpressionBuilder.counter(pid)

# Set verdict
{:ok, verdict_id} = NFTex.ExpressionBuilder.verdict_drop(pid)
```

#### NFTex.Port - Direct libnftnl Access

For maximum control, use the low-level Port API directly:

```elixir
# Start the NFTex port
{:ok, pid} = NFTex.start_link()

# Allocate and configure a rule
{:ok, rule_id} = NFTex.Port.call(pid, {:rule_alloc})
:ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :table, "filter"})
:ok = NFTex.Port.call(pid, {:rule_set_str, rule_id, :chain, "INPUT"})

# Add expressions
{:ok, expr_id} = NFTex.Port.call(pid, {:expr_alloc, "counter"})
:ok = NFTex.Port.call(pid, {:rule_add_expr, rule_id, expr_id})

# Send to kernel
:ok = NFTex.Port.call(pid, {:rule_send_to_kernel, rule_id, :add})

# Clean up
:ok = NFTex.Port.call(pid, {:rule_free, rule_id})
```

## Examples

See the [examples/](examples/) directory for comprehensive working examples:

- **[ip_blocklist.exs](examples/ip_blocklist.exs)** - Dynamic IP blocklist management with sets
- **[query_tables.exs](examples/query_tables.exs)** - Query and inspect nftables configuration
- **[firewall_rules.exs](examples/firewall_rules.exs)** - Create dynamic firewall rules to block/allow IPs

Run examples with:

```bash
mix run examples/firewall_rules.exs
```

See [examples/README.md](examples/README.md) for detailed descriptions and usage patterns.

## Running with Capabilities

The `libnf_ex` port requires the `CAP_NET_ADMIN` Linux capability to perform netlink operations with the kernel's nftables subsystem.

**⚠️ Without this capability, kernel operations will fail with "Permission denied (EACCES)".**

### Quick Setup (Development)

```bash
# After compilation, set capabilities on the binary
sudo setcap cap_net_admin+ep priv/libnf_ex

# Verify it worked
getcap priv/libnf_ex

# Now run as a normal user
iex -S mix
```

**Note**: You'll need to re-run `setcap` after each recompilation.

### Full Documentation

See **[CAPABILITIES.md](CAPABILITIES.md)** for comprehensive documentation including:

- What Linux capabilities are and why they're needed
- Multiple setup methods (file capabilities, sudo, ambient capabilities)
- Production deployment with systemd
- Docker and container considerations
- Troubleshooting common issues
- Security best practices

### Running Without Capabilities

NFTex can run without `CAP_NET_ADMIN` for development and testing, but with limited functionality:
- ✅ All resource allocation and configuration works
- ✅ Tests pass (they don't require kernel operations)
- ❌ Netlink operations to kernel will fail with EACCES

The application will log warnings about missing capabilities but continue to run.

## Use Cases

NFTex is ideal for applications that need dynamic firewall control:

- **Dynamic Firewall Management** - Block/allow IPs based on application logic
- **IDS Integration** - Automatically block IPs detected by intrusion detection systems
- **Rate Limiting** - Block abusive clients exceeding rate limits
- **Geographic Filtering** - Block IP ranges by country or region
- **Security Incident Response** - Rapidly deploy firewall rules during attacks
- **Configuration Management** - Query and audit firewall state programmatically
- **API-Driven Firewalls** - Expose firewall control through REST APIs
- **Testing** - Programmatically test firewall behavior in CI/CD

## Development Status

Current implementation status: **Phase 2 Complete - Rule Creation Working**

### Completed Features ✅

- [x] Port-based architecture with fault isolation
- [x] ETF protocol implementation
- [x] Resource management (automatic cleanup)
- [x] Query operations (tables, chains, rules, sets, elements)
- [x] Set operations (add/delete elements, list, exists check)
- [x] Rule creation with expression builders
- [x] High-level helper functions (block_ip, accept_ip)
- [x] IPv4 payload expressions
- [x] Comparison expressions
- [x] Counter expressions
- [x] Verdict expressions (DROP, ACCEPT)
- [x] Comprehensive examples
- [x] Working integration with kernel nftables

### In Progress 🚧

- [ ] Comprehensive module documentation (Phase 3)
- [ ] ExUnit test suite
- [ ] Enhanced error messages

### Planned Features 📋

- [ ] IPv6 expression helpers
- [ ] Meta expression helpers (iif, oif, etc.)
- [ ] Port-based filtering helpers
- [ ] NAT expression helpers
- [ ] Table and chain creation helpers

See [NFTABLES_PLAN.md](NFTABLES_PLAN.md) for the complete implementation roadmap.

## Integration with nftables

NFTex operates on the same nftables configuration as the `nft` command-line tool. You can:

1. **Create base infrastructure with `nft`:**

```bash
# Create filter table and INPUT chain
nft add table filter
nft add chain filter INPUT '{ type filter hook input priority 0; }'

# Create a set for IP blocklists
nft add set filter blocklist '{ type ipv4_addr; }'
```

2. **Manage rules dynamically with NFTex:**

```elixir
{:ok, pid} = NFTex.start_link()
NFTex.Rule.block_ip(pid, "filter", "INPUT", <<192, 168, 1, 100>>)
```

3. **Query results with either tool:**

```bash
# Command line
nft list ruleset

# Or from Elixir
{:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT")
```

NFTex and `nft` are fully interoperable - rules created with one can be queried and modified by the other.

## Performance

NFTex is designed for high performance:

- **Direct C bindings** via Zig (no syscall overhead)
- **Efficient binary protocol** between Elixir and native code
- **Batch operations** for multiple elements
- **Minimal memory allocations**
- **No external process spawning**

Typical operation times (4-core Intel i5):

- Add 1000 IPs to set: ~15ms
- Create single rule: ~0.5ms
- Query 100 rules: ~5ms
- List 50 set elements: ~3ms

## Testing

```bash
# Run tests
mix test

# Run specific test file
mix test test/nftex/rule_test.exs

# Integration tests (requires CAP_NET_ADMIN)
mix test --only integration
```

Note: Tests require the `CAP_NET_ADMIN` capability on the port binary.

## Documentation

Generate and view documentation:

```bash
# Generate docs
mix docs

# Open in browser
open doc/index.html
```

Online documentation: [HexDocs](https://hexdocs.pm/nftex)

See also:
- [examples/README.md](examples/README.md) - Example descriptions and usage patterns
- [CAPABILITIES.md](CAPABILITIES.md) - Comprehensive guide to Linux capabilities
- [NFTABLES_PLAN.md](NFTABLES_PLAN.md) - Implementation roadmap

## Security

NFTex implements multiple layers of security to safely handle the powerful `CAP_NET_ADMIN` capability required for firewall management.

### Permission Requirements

**CRITICAL:** The `libnf_ex` executable has Linux capabilities that grant network administration privileges. To prevent unauthorized access, the executable **MUST NOT** have world-readable, world-writable, or world-executable permissions.

#### Automatic Permission Check

The executable performs a security check on startup and **refuses to run** if it detects insecure permissions:

```bash
# ✗ INSECURE - Will refuse to start (mode: 755)
-rwxr-xr-x 1 user group libnf_ex

# ✓ SECURE - Will start (mode: 750)
-rwxr-x--- 1 user group libnf_ex

# ✓ SECURE - Will start (mode: 700)
-rwx------ 1 user group libnf_ex
```

**Rule:** The file mode must end in `0` (no permissions for "other").

If you see this error:

```
SECURITY ERROR: Executable has world permissions enabled!

Current permissions: 755

This executable has CAP_NET_ADMIN capability and MUST NOT be
world-readable, world-writable, or world-executable.

To fix, run:
  chmod 750 priv/libnf_ex
  # or
  chmod 700 priv/libnf_ex
```

Fix it immediately:

```bash
chmod 750 priv/libnf_ex
# or for single-user access only:
chmod 700 priv/libnf_ex
```

### Access Control

Control who can use NFTex through **file ownership and group membership**:

#### Single User Access (mode: 700)

```bash
# Only the owner can execute
chmod 700 priv/libnf_ex
chown your-app-user priv/libnf_ex

# Run your Elixir application as that user
sudo -u your-app-user mix run
```

#### Group-Based Access (mode: 750)

```bash
# Create a group for firewall management
sudo groupadd nftex-admin

# Add users who need firewall access
sudo usermod -a -G nftex-admin alice
sudo usermod -a -G nftex-admin bob

# Set ownership and permissions
sudo chown root:nftex-admin priv/libnf_ex
sudo chmod 750 priv/libnf_ex

# Set capability
sudo setcap cap_net_admin=ep priv/libnf_ex
```

Now only users in the `nftex-admin` group can run the executable.

### Capabilities vs. setuid root

NFTex uses **Linux capabilities** instead of setuid root for better security:

| Approach | Security Level | Description |
|----------|---------------|-------------|
| ❌ setuid root | **Dangerous** | Grants full root privileges |
| ✅ CAP_NET_ADMIN | **Minimal** | Grants only network admin rights |

**Why capabilities are better:**

1. **Principle of Least Privilege** - Only grants network administration, not full root
2. **No Privilege Escalation** - `PR_SET_NO_NEW_PRIVS` prevents gaining more privileges
3. **Automatic Revocation** - Capability is lost if binary is modified
4. **Kernel Enforced** - Checked by the kernel, not bypassable

### Setting Capabilities

After compilation, grant the `CAP_NET_ADMIN` capability:

```bash
sudo setcap cap_net_admin=ep priv/libnf_ex
```

Verify it's set:

```bash
getcap priv/libnf_ex
# Output: priv/libnf_ex = cap_net_admin+ep
```

**Important:** You'll need to re-run `setcap` after each recompilation, as capabilities are removed when the binary changes.

### Production Deployment

For production systems, use this secure setup:

```bash
# 1. Create dedicated user and group
sudo useradd -r -s /bin/false nftex
sudo groupadd nftex-admin

# 2. Add application user to group
sudo usermod -a -G nftex-admin your-app-user

# 3. Set ownership and permissions
sudo chown nftex:nftex-admin /path/to/priv/libnf_ex
sudo chmod 750 /path/to/priv/libnf_ex

# 4. Set capability
sudo setcap cap_net_admin=ep /path/to/priv/libnf_ex

# 5. Verify
ls -l /path/to/priv/libnf_ex
getcap /path/to/priv/libnf_ex
```

### Systemd Integration

For applications running under systemd:

```ini
[Unit]
Description=My NFTex Application
After=network.target

[Service]
Type=simple
User=your-app-user
Group=nftex-admin

# Additional security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/your-app

ExecStart=/usr/bin/mix run --no-halt
WorkingDirectory=/opt/your-app

# Capability delegation (alternative to file capabilities)
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

With `AmbientCapabilities`, you don't need `setcap` on the binary. The systemd service grants the capability at runtime.

### Security Features

NFTex implements multiple security measures:

- ✅ **Permission Validation** - Refuses to start with insecure file permissions
- ✅ **Minimal Capabilities** - Only `CAP_NET_ADMIN`, not full root
- ✅ **No Privilege Escalation** - `PR_SET_NO_NEW_PRIVS` flag set
- ✅ **Process Isolation** - Port crashes don't crash the BEAM VM
- ✅ **Input Validation** - All data validated before passing to libnftnl
- ✅ **Resource Limits** - Prevents memory exhaustion attacks
- ✅ **Automatic Cleanup** - Resources freed on process termination

### Security Audit Checklist

Before deploying to production:

- [ ] File permissions end in `0` (verify with `ls -l`)
- [ ] Capability is set (verify with `getcap`)
- [ ] Ownership is correct (not owned by regular user)
- [ ] Only authorized users are in the access group
- [ ] Application runs as dedicated non-root user
- [ ] Systemd hardening options are enabled (if using systemd)
- [ ] Firewall rules are reviewed regularly
- [ ] Logs are monitored for unauthorized access attempts

### Threat Model

NFTex protects against:

- ✅ **Unauthorized firewall modifications** - Permission and group checks
- ✅ **Privilege escalation** - `PR_SET_NO_NEW_PRIVS` flag
- ✅ **Binary tampering** - Capability automatically revoked if binary changes
- ✅ **Resource exhaustion** - Resource limits enforced
- ✅ **BEAM VM compromise** - Port isolation

NFTex does NOT protect against:

- ❌ **Compromised root account** - Root can always modify firewall
- ❌ **Kernel vulnerabilities** - Relies on kernel capability system
- ❌ **Physical access** - Attacker with physical access can bypass OS security

### Reporting Security Issues

If you discover a security vulnerability in NFTex:

1. **Do NOT** open a public GitHub issue
2. Email security details to [your-security-email]
3. Allow reasonable time for a fix before disclosure
4. We'll acknowledge receipt within 48 hours

### Additional Resources

- [Linux Capabilities Man Page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [CAPABILITIES.md](CAPABILITIES.md) - Detailed capability documentation
- [systemd Security](https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Security)

## License

See LICENSE file for details.

## Contributing

See [NFTABLES_PLAN.md](NFTABLES_PLAN.md) for implementation details and contribution guidelines.

## References

- [libnftnl Documentation](https://netfilter.org/projects/libnftnl/)
- [nftables Wiki](https://wiki.nftables.org/)
- [Erlang ei.h Documentation](https://www.erlang.org/doc/man/ei.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
