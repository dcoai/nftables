# NFTex - Elixir Interface to nftables

High-performance Elixir bindings for Linux nftables via the official libnftables JSON API. NFTex provides both high-level helper functions for common firewall operations and flexible rule building with familiar nft syntax.

## Features

- **Official API** - Uses libnftables JSON API (no manual netlink messages)
- **High-Level APIs** - Simple functions for blocking IPs, managing sets, creating rules
- **Sysctl Management** - Safe read/write access to network kernel parameters
- **Hybrid Approach** - JSON for data operations, nft syntax for complex rules
- **Distributed Firewall Support** - Build commands centrally, execute on multiple nodes
- **Command/Execution Separation** - Build JSON/nft commands without executing
- **Batch Operations** - Atomic multi-command execution
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
:ok = NFTex.Table.add(pid, %{name: "filter", family: :inet})
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

### Block an IP Address (New API)

```elixir
# Start NFTex
{:ok, pid} = NFTablesEx.start_link()

# Build and execute a rule to block an IP
alias NFTablesEx.{Builder, Rule}

Builder.new(family: :inet)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.source("192.168.1.100")
  |> Rule.drop()
  |> Rule.to_expr()
)
|> Builder.execute(pid)

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

### Build Complex Rules (New API)

```elixir
alias NFTablesEx.{Builder, Rule}

# Build a sophisticated firewall rule with the new fluent API
:ok = Builder.new(family: :inet)
  |> Builder.set_table("filter")
  |> Builder.set_chain("INPUT")
  |> Builder.add_rule(
    Rule.new()
    |> Rule.source("10.0.0.0/8")
    |> Rule.protocol(:tcp)
    |> Rule.dport(22)
    |> Rule.state([:new])
    |> Rule.limit(10, :minute, burst: 5)
    |> Rule.log("SSH_ACCESS: ", level: "info")
    |> Rule.counter()
    |> Rule.accept()
    |> Rule.to_expr()
  )
  |> Builder.execute(pid)

# Or build multiple rules in a batch
:ok = Builder.new(family: :inet)
  |> Builder.add_table("filter")
  |> Builder.add_chain("INPUT")
  |> Builder.set_table("filter")
  |> Builder.set_chain("INPUT")
  |> Builder.add_rule(
    Rule.new() |> Rule.source("10.0.0.0/8") |> Rule.drop() |> Rule.to_expr()
  )
  |> Builder.add_rule(
    Rule.new() |> Rule.state([:established, :related]) |> Rule.accept() |> Rule.to_expr()
  )
  |> Builder.execute(pid)
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

## New Builder + Rule API

NFTablesEx now provides a powerful, composable API for building firewall rules:

### Builder Module - Command Construction

The `Builder` module provides a pure functional interface for constructing nftables commands:

```elixir
alias NFTablesEx.Builder

# Build commands without executing
builder = Builder.new(family: :inet)
|> Builder.add_table("filter")
|> Builder.add_chain("INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")

# Execute when ready
:ok = Builder.execute(builder, pid)

# Or inspect the JSON that would be sent
json = Builder.to_json(builder)
```

### Rule Module - Expression Building

The `Rule` module provides a fluent API for building rule expressions:

```elixir
alias NFTablesEx.Rule

# Build rule expressions
expr = Rule.new()
|> Rule.source("10.0.0.0/8")           # Match source IP/CIDR
|> Rule.protocol(:tcp)                   # Match protocol
|> Rule.dport(22)                        # Match destination port
|> Rule.state([:established, :related]) # Match connection state
|> Rule.limit(10, :minute, burst: 5)    # Rate limiting
|> Rule.log("SSH: ", level: "info")     # Logging
|> Rule.counter()                        # Add counter
|> Rule.accept()                         # Verdict
|> Rule.to_expr()                        # Convert to expression list

# Use with Builder
Builder.new(family: :inet)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(expr)
|> Builder.execute(pid)
```

### Available Rule Matchers

- **IP**: `source/1`, `dest/1` - Supports single IPs and CIDR notation
- **Ports**: `sport/1`, `dport/1`, `port/1` - TCP/UDP ports
- **Protocol**: `protocol/1` - tcp, udp, icmp, etc.
- **State**: `state/1` - Connection tracking states
- **Interface**: `iif/1`, `oif/1` - Input/output interfaces
- **TCP Flags**: `tcp_flags/2` - SYN, ACK, FIN, etc.
- **Many more**: See module documentation

### Available Actions & Verdicts

- **Actions**: `counter/0`, `log/2`, `limit/3`, `set_mark/1`
- **Verdicts**: `accept/0`, `drop/0`, `reject/1`, `jump/1`, `return/0`
- **NAT**: `snat/2`, `dnat/2`, `masquerade/1`

### Advanced Features - Named Objects

The `Builder` module also supports nftables named objects for advanced use cases:

#### Maps (Key-Value Dictionaries)

Maps allow you to create dynamic mappings from keys to values (e.g., port → verdict):

```elixir
# Create a map that maps ports to verdicts
Builder.new()
|> Builder.add_table("filter")
|> Builder.add_map("port_verdict", type: {:inet_service, :verdict})
|> Builder.add_map_elements("port_verdict", [
  {80, "accept"},
  {443, "accept"},
  {8080, "drop"}
])
|> Builder.execute(pid)

# Use the map in a rule
Builder.new()
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.protocol(:tcp)
  |> Rule.dport_map("port_verdict")  # Map lookup
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

#### Named Counters

Named counters can be shared across multiple rules and queried independently:

```elixir
# Create a named counter
Builder.new()
|> Builder.add_table("filter")
|> Builder.add_counter("http_traffic")
|> Builder.execute(pid)

# Reference it in rules
Builder.new()
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.protocol(:tcp)
  |> Rule.dport(80)
  |> Rule.counter_ref("http_traffic")  # Reference named counter
  |> Rule.accept()
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

#### Quotas

Quotas limit the total amount of traffic (in bytes) that can pass through:

```elixir
# Create a 1 GB quota
Builder.new()
|> Builder.add_table("filter")
|> Builder.add_quota("monthly_limit", 1_000_000_000)
|> Builder.execute(pid)

# Use in a rule - traffic stops when quota exceeded
Builder.new()
|> Builder.set_table("filter")
|> Builder.set_chain("OUTPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.quota_ref("monthly_limit")
  |> Rule.accept()
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

#### Named Limits

Named limits provide reusable rate limiting across multiple rules:

```elixir
# Create a rate limit object
Builder.new()
|> Builder.add_table("filter")
|> Builder.add_limit("ssh_limit", 10, :minute, burst: 5)
|> Builder.execute(pid)

# Use in multiple rules
Builder.new()
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.protocol(:tcp)
  |> Rule.dport(22)
  |> Rule.limit_ref("ssh_limit")  # Reference named limit
  |> Rule.accept()
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

**Benefits of Named Objects:**
- **Reusability**: Define once, use in multiple rules
- **Dynamic Updates**: Update the object without modifying rules
- **Queryable**: Check counter values, quota usage independently
- **Performance**: More efficient than inline expressions for shared logic

## Migration Guide: Old API → New API

If you're upgrading from the old convenience functions, here's how to migrate to the new Builder + Rule API:

### Blocking an IP Address

**Old API:**
```elixir
Rule.block_ip(pid, "filter", "INPUT", "192.168.1.100")
```

**New API:**
```elixir
Builder.new(family: :inet)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.source("192.168.1.100")
  |> Rule.drop()
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

### Accepting an IP Address

**Old API:**
```elixir
Rule.accept_ip(pid, "filter", "INPUT", "10.0.0.1")
```

**New API:**
```elixir
Builder.new(family: :inet)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.source("10.0.0.1")
  |> Rule.accept()
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

### Rate Limiting

**Old API:**
```elixir
Rule.rate_limit(pid, "filter", "INPUT", 10, :minute, burst: 5)
```

**New API:**
```elixir
Builder.new(family: :inet)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(
  Rule.new()
  |> Rule.limit(10, :minute, burst: 5)
  |> Rule.drop()  # or accept() depending on your use case
  |> Rule.to_expr()
)
|> Builder.execute(pid)
```

### Deleting Rules

**Old API:**
```elixir
Rule.delete(pid, "filter", "INPUT", :inet, handle)
```

**New API:**
```elixir
# Query for rules first
{:ok, rules} = Query.list_rules(pid, "filter", "INPUT", family: :inet)

# Find the rule you want to delete and use Builder
rule = Enum.find(rules, fn r -> r.handle == target_handle end)

Builder.new(family: :inet)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.delete_rule(rule.handle)
|> Builder.execute(pid)
```

### Benefits of the New API

1. **Composability**: Build complex rules by chaining matchers and actions
2. **Type Safety**: Better compile-time validation of rule structure
3. **Testability**: Separate command building from execution
4. **Clarity**: Clear separation between matchers (source, protocol) and verdicts (accept, drop)
5. **CIDR Support**: Native support for CIDR notation like `"10.0.0.0/8"`
6. **Distributed Firewall**: Build commands centrally, execute on multiple nodes
7. **Batch Operations**: Combine multiple operations atomically

### Query Operations

**Old API:**
```elixir
Rule.list(pid, "filter", "INPUT", family: :inet)
```

**New API:**
```elixir
Query.list_rules(pid, "filter", "INPUT", family: :inet)
```

The Query module now handles all listing operations:
- `Query.list_tables/2`
- `Query.list_chains/3`
- `Query.list_rules/4`
- `Query.list_sets/3`

## Core Modules

### NFTex.Table - Table Management

```elixir
# Create a table
:ok = NFTex.Table.add(pid, %{name: "filter", family: :inet})

# Delete a table
:ok = NFTex.Table.delete(pid, "filter", :inet)

# List tables
{:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)
```

### NFTex.Chain - Chain Management

```elixir
# Create a base chain with hook
:ok = NFTex.Chain.add(pid, %{
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
:ok = NFTex.Set.add(pid, %{
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

### NFTex.Rule - Rule Expression Building

The `Rule` module now provides a fluent API for building rule expressions:

```elixir
alias NFTablesEx.{Builder, Rule}

# Build complex rules using the fluent API
:ok = Builder.new(family: :inet)
  |> Builder.set_table("filter")
  |> Builder.set_chain("INPUT")
  |> Builder.add_rule(
    Rule.new()
    |> Rule.source("192.168.1.100")
    |> Rule.protocol(:tcp)
    |> Rule.dport(80)
    |> Rule.drop()
    |> Rule.to_expr()
  )
  |> Builder.execute(pid)

# List rules using Query module
{:ok, rules} = NFTex.Query.list_rules(pid, "filter", "INPUT", family: :inet)
```

**Note**: The old `Rule.block_ip/4`, `Rule.accept_ip/4`, `Rule.rate_limit/6`, and `Rule.delete/5` functions are deprecated. See the Migration Guide above for how to use the new Builder + Rule API.

### NFTex.RuleBuilder - Fluent Rule Construction

```elixir
alias NFTex.RuleBuilder

# Build complex rules with chainable API
:ok = RuleBuilder.new(pid, "filter", "INPUT")
  |> RuleBuilder.match_source_ip("192.168.1.100")
  |> RuleBuilder.match_dest_port(22)
  |> RuleBuilder.rate_limit(5, :minute)
  |> RuleBuilder.counter()
  |> RuleBuilder.drop()
  |> RuleBuilder.commit()
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

### NFTex.Sysctl - Network Parameter Management

NFTex provides safe, whitelist-based access to kernel network parameters via `/proc/sys/net/*`. All operations use the existing CAP_NET_ADMIN capability.

```elixir
alias NFTex.{Sysctl, Sysctl.Network}

# Low-level API - direct parameter access
{:ok, "0"} = Sysctl.get(pid, "net.ipv4.ip_forward")
:ok = Sysctl.set(pid, "net.ipv4.ip_forward", "1")

# High-level helpers for common operations
:ok = Network.enable_ipv4_forwarding(pid)
:ok = Network.enable_ipv6_forwarding(pid)
:ok = Network.enable_syncookies(pid)

# Check forwarding status
{:ok, true} = Network.ipv4_forwarding_enabled?(pid)

# Connection tracking configuration
:ok = Network.set_conntrack_max(pid, 131072)
{:ok, 131072} = Network.get_conntrack_max(pid)

# ICMP configuration
:ok = Network.ignore_ping(pid)  # Stealth mode
:ok = Network.allow_ping(pid)   # Normal mode

# Composite operations
:ok = Network.configure_router(pid,
  ipv4_forwarding: true,
  ipv6_forwarding: true,
  syncookies: true,
  send_redirects: false
)

:ok = Network.harden_security(pid)
```

**Security Features:**
- Parameter whitelist (44 network-related parameters)
- Value validation per parameter type
- Limited to `/proc/sys/net/*` only
- Uses existing CAP_NET_ADMIN capability

**Supported Parameters:**
- IPv4/IPv6 forwarding and configuration
- TCP settings (syncookies, timestamps, keepalive, etc.)
- Connection tracking (nf_conntrack)
- ICMP settings
- Security parameters (rp_filter, source routing, redirects)

See `NFTex.Sysctl` and `NFTex.Sysctl.Network` documentation for the complete parameter list.

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
alias NFTex.RuleBuilder

# Track connection state
:ok = RuleBuilder.new(pid, "filter", "INPUT")
  |> RuleBuilder.match_ct_state([:established, :related])
  |> RuleBuilder.accept()
  |> RuleBuilder.commit()

# Connection limits
:ok = RuleBuilder.new(pid, "filter", "INPUT")
  |> RuleBuilder.match_dest_port(80)
  |> RuleBuilder.match_ct_state([:new])
  |> RuleBuilder.limit_connections(100)  # Max 100 concurrent connections
  |> RuleBuilder.drop()
  |> RuleBuilder.commit()

# Track connection bytes
:ok = RuleBuilder.new(pid, "filter", "FORWARD")
  |> RuleBuilder.match_ct_bytes(:gt, 1_000_000)  # Over 1MB
  |> RuleBuilder.log("LARGE_TRANSFER: ")
  |> RuleBuilder.accept()
  |> RuleBuilder.commit()
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

## Distributed Firewall Support

NFTex supports distributed firewall architectures where a central command & control node generates firewall rules and sends them to multiple firewall nodes for execution. This is achieved through separation of command building and execution.

### Architecture

```
┌──────────────────────────────┐
│  C&C Node                    │
│  (NFTex Library)             │
│                              │
│  - Builds firewall rules     │
│  - Generates JSON/nft cmds   │
│  - Sends to firewall nodes   │
└──────────┬───────────────────┘
           │
           │ JSON/nft commands over network
           │ (your transport)
           │
           ▼
┌──────────────────────────────┐
│  Firewall Node 1, 2, 3...    │
│  (Minimal Shim + Port)       │
│                              │
│  - Receives commands         │
│  - Executes via port         │
│  - Returns results           │
└──────────────────────────────┘
```

### Command Building Without Execution

All high-level modules now provide `build_*` functions that generate commands without executing them:

```elixir
# Build commands without executing
table_cmd = NFTex.Table.build_add(%{name: "filter", family: :inet})
chain_cmd = NFTex.Chain.build_add(%{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
})
rule_cmd = NFTex.Rule.build_block_ip("filter", "INPUT", "192.168.1.100")

# Each command is a JSON or nft syntax string ready to execute
```

### Batch Operations

Combine multiple commands into atomic batches:

```elixir
alias NFTex.Batch

# Build a batch of operations
batch = Batch.new()
|> Batch.add(NFTex.Table.build_add(%{name: "filter", family: :inet}))
|> Batch.add(NFTex.Chain.build_add(%{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
}))
|> Batch.add(NFTex.Rule.build_block_ip("filter", "INPUT", "1.2.3.4"))
|> Batch.add(NFTex.Rule.build_block_ip("filter", "INPUT", "5.6.7.8"))

# Execute locally
{:ok, response} = Batch.execute(batch, pid: pid)

# Or convert to JSON for remote execution
json = Batch.to_json(batch)
MyTransport.send_to_node("firewall-1", json)
```

### Execution Abstraction

The `NFTex.Executor` module provides clean command execution:

```elixir
# Local execution
json_cmd = NFTex.Table.build_add(%{name: "filter", family: :inet})
{:ok, response} = NFTex.Executor.execute(json_cmd, pid: pid)

# Or use execute! for exceptions instead of tuples
response = NFTex.Executor.execute!(json_cmd, pid: pid)
```

### RuleBuilder for Remote Execution

The fluent RuleBuilder API can generate commands without committing:

```elixir
alias NFTex.RuleBuilder

# Build complex rule without executing
cmd = RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_source_ip("192.168.1.100")
|> RuleBuilder.match_dest_port(22)
|> RuleBuilder.rate_limit(10, :minute)
|> RuleBuilder.log("SSH_ATTACK: ")
|> RuleBuilder.drop()
|> RuleBuilder.to_nft_command()  # Returns nft command string

# Send to remote nodes
MyTransport.send_to_node("firewall-1", cmd)
MyTransport.send_to_node("firewall-2", cmd)
MyTransport.send_to_node("firewall-3", cmd)
```

### Build Functions Reference

#### Table Operations

```elixir
# Build table commands
table_create = NFTex.Table.build_add(%{name: "filter", family: :inet})
table_delete = NFTex.Table.build_delete("filter", :inet)
```

#### Chain Operations

```elixir
# Build chain commands
chain_create = NFTex.Chain.build_add(%{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
})
chain_delete = NFTex.Chain.build_delete("filter", "INPUT", :inet)
```

#### Set Operations

```elixir
# Build set commands
set_create = NFTex.Set.build_add(%{
  name: "blocklist",
  table: "filter",
  family: :inet,
  key_type: :ipv4_addr
})
set_add = NFTex.Set.build_add_elements("filter", "blocklist", :inet, [
  "192.168.1.100",
  "10.0.0.50"
])
set_delete_elem = NFTex.Set.build_delete_elements("filter", "blocklist", :inet, [
  "192.168.1.100"
])
set_delete = NFTex.Set.build_delete("filter", "blocklist", :inet)
```

#### Rule Operations

```elixir
# Build rule commands
block_ip = NFTex.Rule.build_block_ip("filter", "INPUT", "192.168.1.100")
accept_ip = NFTex.Rule.build_accept_ip("filter", "INPUT", "10.0.0.1")
block_ipv6 = NFTex.Rule.build_block_ipv6("filter", "INPUT", "2001:db8::1")
rate_limit = NFTex.Rule.build_rate_limit("filter", "INPUT", 10, :second)
```

### Complete Distributed Firewall Example

```elixir
defmodule MyApp.DistributedFirewall do
  alias NFTex.{Batch, Table, Chain, Rule, Set, Executor}

  # On C&C node - build firewall configuration
  def build_firewall_config() do
    Batch.new()
    # Create table
    |> Batch.add(Table.build_add(%{name: "filter", family: :inet}))
    # Create INPUT chain
    |> Batch.add(Chain.build_add(%{
      table: "filter",
      name: "INPUT",
      family: :inet,
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :drop
    }))
    # Create blocklist set
    |> Batch.add(Set.build_add(%{
      name: "blocklist",
      table: "filter",
      family: :inet,
      key_type: :ipv4_addr
    }))
    # Add malicious IPs to blocklist
    |> Batch.add(Set.build_add_elements("filter", "blocklist", :inet, [
      "1.2.3.4",
      "5.6.7.8"
    ]))
    # Allow loopback
    |> Batch.add(Rule.build_accept_ip("filter", "INPUT", "127.0.0.1"))
    # Rate limit SSH
    |> Batch.add(Rule.build_rate_limit("filter", "INPUT", 10, :minute))
  end

  # On C&C node - deploy to multiple firewalls
  def deploy_to_firewalls(firewall_nodes) do
    config_batch = build_firewall_config()
    json_cmd = Batch.to_json(config_batch)

    # Send to all firewall nodes
    Enum.map(firewall_nodes, fn node ->
      Task.async(fn ->
        MyTransport.send_to_node(node, json_cmd)
      end)
    end)
    |> Task.await_many(timeout: 10_000)
  end

  # On firewall nodes - minimal shim
  def execute_received_command(json_cmd) do
    {:ok, pid} = NFTex.start_link()
    Executor.execute(json_cmd, pid: pid)
  end
end

# Deploy firewall rules to 3 nodes
MyApp.DistributedFirewall.deploy_to_firewalls([
  "firewall-1.local",
  "firewall-2.local",
  "firewall-3.local"
])
```

### Key Benefits

- **Incremental Updates** - Each operation generates one minimal command
- **Atomic Batches** - Multiple commands executed atomically (all-or-nothing)
- **Transport Agnostic** - Use any network transport (Phoenix PubSub, gRPC, etc.)
- **Centralized Logic** - Firewall policy managed from single C&C node
- **Minimal Remote Footprint** - Firewall nodes only need port + minimal shim
- **Fault Tolerant** - Port crashes isolated from BEAM VM

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
