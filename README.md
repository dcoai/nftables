# NFTex - Elixir Interface to nftables

High-performance Elixir bindings for Linux nftables via the official libnftables JSON API. NFTex provides both high-level helper functions for common firewall operations and flexible rule building with familiar nft syntax.

## Features

- **Official API** - Uses libnftables JSON API (no manual netlink messages)
- **High-Level APIs** - Simple functions for blocking IPs, managing sets, creating rules
- **Hybrid Approach** - JSON for data operations, nft syntax for complex rules
- **Dynamic Firewall Management** - Modify firewall rules from your Elixir application
- **IP Blocklist Management** - Add/remove IPs from blocklists with one function call
- **Query Operations** - List tables, chains, rules, sets, and elements
- **Fluent RuleBuilder** - Chainable API for intuitive rule construction
- **Policy Module** - Pre-built firewall policies (SSH, HTTP, rate limiting, etc.)
- **Port-based Architecture** - Fault isolation (crashes don't affect BEAM VM)
- **Secure** - Port runs with minimal privileges (CAP_NET_ADMIN only)
- **Zero Dependencies** - Direct bindings to libnftables, no external processes
- **Fast** - JSON-based communication proven 41-5000% faster than ETF in benchmarks

## Architecture

```
┌─────────────────────────────────────┐
│  Elixir Application                 │
│  (NFTex.Table, Chain, Rule, Set)    │
└────────────┬────────────────────────┘
             │
             ├─ Tables/Chains/Sets
             │  └─> JSONBuilder (JSON format)
             │      └─> Port.call(json_string)
             │
             └─ Rules
                └─> "add rule inet table chain expr"
                    └─> Port.call(nft_command)
                        │
                        ▼
        ┌───────────────────────────────────┐
        │  Zig Port (port.zig)              │
        │  libnftables.nft_run_cmd_from_buf │
        │  (accepts JSON OR nft syntax!)    │
        └───────────┬───────────────────────┘
                    │
                    ▼
        ┌───────────────────────────┐
        │  libnftables (C library)  │
        │  - Parses JSON format     │
        │  - Parses nft syntax      │
        │  - Converts to netlink    │
        │  - Sends to kernel        │
        └───────────────────────────┘
```

### Hybrid Approach

NFTex uses a **hybrid approach** for optimal simplicity:

- **JSON format** for structured data (tables, chains, sets)
- **nft syntax** for complex rules (simpler than JSON expressions)

Both formats are processed by the same `libnftables.nft_run_cmd_from_buffer()` function.

### JSON-Only Port

NFTex uses a unified JSON-based port for all communication:

```elixir
{:ok, pid} = NFTex.start_link()

# Send JSON commands (for structured operations)
json_cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
{:ok, json_response} = NFTex.Port.call(pid, json_cmd)

# Or use high-level APIs that handle JSON internally
:ok = NFTex.Table.create(pid, %{name: "filter", family: :inet})
```

**Benefits:**
- ✅ Simple, text-based protocol
- ✅ JSON proven faster in benchmarks (41-5000% vs ETF)
- ✅ Direct compatibility with libnftables
- ✅ Easy to debug and inspect

## System Requirements

- Linux kernel >= 3.18 (nf_tables support)
- Zig >= 0.11.0
- Elixir >= 1.14
- Erlang/OTP >= 24

### Required System Libraries

The following development packages must be installed:

- `libnftables-dev` >= 0.9.0 - Netfilter nftables userspace library (includes JSON API)
- `libcap-dev` >= 2.25 - POSIX capabilities library

### Installation on Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  libnftables-dev \
  libcap-dev \
  zig
```

### Verify Installation

Check that all dependencies are available:

```bash
# Check Zig
zig version

# Check nftables library
pkg-config --modversion libnftables

# Check capability library
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

The compiled `port_nftables` binary will be placed in `priv/port_nftables`.

### Manual Build

To build just the Zig port:

```bash
cd native
zig build
```

The binary will be in `native/zig-out/bin/port_nftables`.

### Setting Capabilities

The port binary needs CAP_NET_ADMIN capability to manage firewall rules:

```bash
sudo setcap cap_net_admin=ep priv/port_nftables
```

Verify:

```bash
getcap priv/port_nftables
# Should show: priv/port_nftables = cap_net_admin+ep
```

## Quick Start

### Block an IP Address

```elixir
# Start NFTex
{:ok, pid} = NFTex.start_link()

# Block a malicious IP
ip = "192.168.1.100"
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

# That's it! The rule is now active in the kernel.
```

### Manage IP Blocklists with Sets

```elixir
{:ok, pid} = NFTex.start_link()

# Add IPs to an existing blocklist set
malicious_ips = [
  "192.168.1.100",
  "10.0.0.99",
  "172.16.5.50"
]

:ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, malicious_ips)

# Remove a false positive
:ok = NFTex.Set.delete_elements(pid, "filter", "blocklist", :inet, ["192.168.1.100"])

# List all blocked IPs
{:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")
```

### Build Complex Rules with RuleBuilder

```elixir
use NFTex.RuleBuilder

# Build a sophisticated firewall rule
rule = new_rule()
  |> match_source_ip("10.0.0.0/8")
  |> match_tcp_dport(22)
  |> limit_rate(10, :minute, burst: 5)
  |> log("SSH_ACCESS", level: :info)
  |> accept()
  |> build!()

:ok = NFTex.Rule.add(pid, %{
  family: :inet,
  table: "filter",
  chain: "INPUT",
  expr: rule
})
```

### Setup Basic Firewall

```elixir
{:ok, pid} = NFTex.start_link()

# One command for secure defaults
:ok = NFTex.Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)

# Creates:
# - DROP policy by default
# - Accept loopback traffic
# - Accept established/related connections
# - Drop invalid packets
# - Allow SSH with rate limiting
# - Allow HTTP and HTTPS
```

## Core Modules

### NFTex.Table - Table Management

```elixir
# Create a table
:ok = NFTex.Table.create(pid, %{name: "filter", family: :inet})

# Delete a table
:ok = NFTex.Table.delete(pid, "filter", :inet)

# List tables
{:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)
```

### NFTex.Chain - Chain Management

```elixir
# Create a base chain with hook
:ok = NFTex.Chain.create(pid, %{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
})

# List chains
{:ok, chains} = NFTex.Query.list_chains(pid, family: :inet)
```

### NFTex.Set - Set Management

```elixir
# Create a set
:ok = NFTex.Set.create(pid, %{
  name: "blocklist",
  table: "filter",
  family: :inet,
  key_type: :ipv4_addr,
  elements: []
})

# Add elements
:ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, [
  "192.168.1.100",
  "10.0.0.50"
])

# List elements
{:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")
```

### NFTex.Rule - Rule Management

```elixir
# Add a rule using nft syntax
:ok = NFTex.Rule.add(pid, %{
  family: :inet,
  table: "filter",
  chain: "INPUT",
  expr: "ip saddr 192.168.1.100 drop"
})

# Helper functions for common operations
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", "192.168.1.100")
:ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", "10.0.0.1")

# List rules
{:ok, rules} = NFTex.Query.list_rules(pid, family: :inet)
```

### NFTex.RuleBuilder - Fluent Rule Construction

```elixir
use NFTex.RuleBuilder

# Build complex rules with chainable API
rule = new_rule()
  |> comment("Block scanner")
  |> match_source_ip("192.168.1.100")
  |> match_tcp_dport(22)
  |> limit_rate(5, :minute)
  |> counter()
  |> drop()
  |> build!()

:ok = NFTex.Rule.add(pid, %{
  family: :inet,
  table: "filter",
  chain: "INPUT",
  expr: rule
})
```

See the [RuleBuilder documentation](lib/nftex/rule_builder.ex) for the full API.

### NFTex.Policy - Pre-built Policies

```elixir
# Quick firewall setup
:ok = NFTex.Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)

# Individual policy helpers
:ok = NFTex.Policy.accept_loopback(pid)
:ok = NFTex.Policy.accept_established(pid)
:ok = NFTex.Policy.drop_invalid(pid)
:ok = NFTex.Policy.allow_ssh(pid, rate_limit: 10)
:ok = NFTex.Policy.allow_http(pid)
:ok = NFTex.Policy.allow_https(pid)
```

## Advanced Usage

### NAT Gateway

```elixir
alias NFTex.NAT

# Setup NAT with masquerading
:ok = NAT.setup_masquerade(pid, %{
  table: "nat",
  out_interface: "eth0",
  masquerade_source: "10.0.0.0/24"
})

# Port forwarding
:ok = NAT.add_port_forward(pid, %{
  table: "nat",
  protocol: :tcp,
  external_port: 8080,
  internal_ip: "10.0.0.10",
  internal_port: 80
})
```

### Connection Tracking

```elixir
use NFTex.RuleBuilder

# Track connection state
rule = new_rule()
  |> match_ct_state([:established, :related])
  |> accept()
  |> build!()

# Connection limits
rule = new_rule()
  |> match_tcp_dport(80)
  |> limit_connections(100)  # Max 100 concurrent connections
  |> accept()
  |> build!()

# Track connection bytes
rule = new_rule()
  |> match_ct_bytes(:>, 1_000_000)  # Over 1MB
  |> log("LARGE_TRANSFER")
  |> accept()
  |> build!()
```

### Raw JSON Commands

For advanced use cases, you can send raw JSON directly:

```elixir
json_cmd = Jason.encode!(%{
  "nftables" => [
    %{
      "add" => %{
        "table" => %{
          "family" => "inet",
          "name" => "custom"
        }
      }
    }
  ]
})

{:ok, response} = NFTex.Port.call(pid, json_cmd)
result = Jason.decode!(response)
```

Or use nft command syntax:

```elixir
nft_command = "add table inet custom"
{:ok, response} = NFTex.Port.call(pid, nft_command)
```

Both are processed by `libnftables.nft_run_cmd_from_buffer()`.

## Examples

The `examples/` directory contains complete, runnable examples:

- `01_basic_firewall.exs` - Complete firewall setup with secure defaults
- `04_rate_limiting.exs` - Rate limiting for DDoS protection
- `07_match_expressions.exs` - Advanced match expressions
- `08_nat_gateway.exs` - NAT gateway configuration
- `09_connection_tracking.exs` - Connection tracking features
- `10_packet_modification.exs` - Packet modification examples
- `firewall_rules.exs` - Dynamic rule management
- `ip_blocklist.exs` - IP blocklist with sets
- `query_tables.exs` - Query operations

Run any example:

```bash
mix run examples/01_basic_firewall.exs
```

## Testing

Run the test suite:

```bash
# Set capability on test binary
sudo setcap cap_net_admin=ep priv/port_nftables

# Run tests
mix test
```

## Security

NFTex follows security best practices:

1. **Minimal Privileges** - Port runs with only CAP_NET_ADMIN capability
2. **Permission Checks** - Port validates file permissions on startup (must not be world-readable/writable/executable)
3. **Input Validation** - All user input is validated before sending to the kernel
4. **Fault Isolation** - Port crashes don't affect the BEAM VM
5. **No Shell Commands** - All operations use libnftables API, no shell execution

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## Performance

Benchmarks show JSON-based communication is significantly faster than ETF (Erlang Term Format):

- Small messages (37 bytes): **JSON 41% faster**
- Medium messages (379 bytes): **JSON 109% faster**
- Large messages (13KB): **JSON 5372% faster**

The JSON-only architecture provides optimal performance while maintaining simplicity.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

See [LICENSE](LICENSE) for details.

## Resources

- [nftables documentation](https://wiki.nftables.org/)
- [libnftables JSON API](https://wiki.nftables.org/wiki-nftables/index.php/JSON_API)
- [nft man page](https://www.netfilter.org/projects/nftables/manpage.html)
- [Netfilter project](https://www.netfilter.org/)

## Credits

Built with:
- [libnftables](https://www.netfilter.org/) - Official nftables library
- [Zig](https://ziglang.org/) - Systems programming language
- [Elixir](https://elixir-lang.org/) - Functional programming language
