# NFTables Usage Rules

## Overview

NFTables provides a pure functional API for building nftables firewall rules via Elixir. This document describes best practices, patterns, and conventions for using the library.

---

## Core Principles

### 1. Pure Functional Match API

The **Match module** is the primary interface for building firewall rules. It follows a **pure functional pattern** with **no side effects**.

**Key Characteristics:**
- **No execution** - Building expressions never modifies the firewall
- **Pure data** - Expressions are plain data structures
- **Composable** - Build expressions in one context, execute in another
- **Testable** - Test expression building without kernel access

**Example:**
```elixir
import NFTables.Match
alias NFTables.{Builder, Executor}

# Build pure expression (no side effects)
expr = rule()
  |> tcp()
  |> dport(22)
  |> accept()
  |> to_expr()

# Execute separately via Builder/Executor
Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

### 2. Builder/Executor Separation

**Clear separation of concerns:**
- **Match** - Builds pure expression data (no execution)
- **Builder** - Constructs complete nftables configurations (no execution)
- **Executor** - Sends configurations to kernel (execution only)

**Pattern:**
```elixir
import NFTables.Match
alias NFTables.{Builder, Executor}

# Step 1: Build expression (Match)
expr = rule() |> tcp() |> dport(80) |> accept() |> to_expr()

# Step 2: Build configuration (Builder)
builder = Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)

# Step 3: Execute (Executor)
Executor.execute(builder, pid)
```

### 3. Dual-Arity Functions

All Match functions support **two arities** for flexibility:

**Arity-1: Start new rule**
```elixir
tcp() |> dport(22) |> accept()
```

**Arity-2: Continue existing rule**
```elixir
builder = rule()
builder = tcp(builder)
builder = dport(builder, 22)
builder = accept(builder)
```

Both patterns work identically. Use whichever is clearer in your context.

---

## Module Organization

### Match Module - Rule Expression Builder

**Purpose:** Build firewall rule expressions as pure data.

**Sub-modules:**
- `Match.IP` - IP address matching (source/dest)
- `Match.Port` - Port matching (TCP/UDP)
- `Match.TCP` - Protocol-specific (flags, TTL)
- `Match.Layer2` - MAC, interfaces, VLAN
- `Match.CT` - Connection tracking
- `Match.Advanced` - ICMP, marks, sets
- `Match.Actions` - Counter, log, rate limit
- `Match.NAT` - SNAT, DNAT, masquerade
- `Match.Verdicts` - accept, drop, reject, jump

**Usage:**
```elixir
import NFTables.Match

# All functions now available without Match. prefix
expr = rule()
  |> source_ip("192.168.1.100")
  |> tcp()
  |> dport(22)
  |> limit(10, :minute)
  |> log("SSH: ")
  |> drop()
  |> to_expr()
```

### Builder Module - Configuration Constructor

**Purpose:** Construct complete nftables configurations without executing.

**Key Functions:**
- `Builder.new/1` - Initialize builder
- `Builder.add_table/2` - Add table
- `Builder.add_chain/3` - Add chain
- `Builder.add_rule/3` - Add rule from Match expression
- `Builder.to_json/1` - Convert to JSON (for inspection or remote execution)
- `Builder.execute/2` - Execute via Executor (convenience)

**Usage:**
```elixir
alias NFTables.Builder

builder = Builder.new(family: :inet)
|> Builder.add_table("filter")
|> Builder.add_chain("INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(expr)

# Execute when ready
Builder.execute(builder, pid)

# Or inspect JSON
json = Builder.to_json(builder)
```

### Executor Module - Command Execution

**Purpose:** Send configurations to kernel via nftables.

**Key Functions:**
- `Executor.execute/2` - Execute Builder or JSON command
- `Executor.execute!/2` - Execute with exception on error

**Usage:**
```elixir
alias NFTables.Executor

# Execute Builder
{:ok, response} = Executor.execute(builder, pid)

# Or with exception on error
response = Executor.execute!(builder, pid)
```

### Policy Module - Pre-built Policies

**Purpose:** Common firewall patterns using Match API internally.

**Key Functions:**
- `Policy.setup_basic_firewall/2` - Complete firewall setup
- `Policy.accept_loopback/1` - Accept lo interface
- `Policy.accept_established/1` - Accept established/related
- `Policy.drop_invalid/1` - Drop invalid packets
- `Policy.allow_ssh/2` - Allow SSH with rate limiting
- `Policy.allow_http/1` - Allow HTTP
- `Policy.allow_https/1` - Allow HTTPS

**Usage:**
```elixir
alias NFTables.Policy

# Quick setup
:ok = Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)

# Or individual policies
:ok = Policy.accept_loopback(pid)
:ok = Policy.accept_established(pid)
:ok = Policy.allow_ssh(pid, rate_limit: 10)
```

### NAT Module - Network Address Translation

**Purpose:** NAT operations (SNAT, DNAT, masquerade, port forwarding).

**Key Functions:**
- `NAT.source_nat/4` - Source NAT
- `NAT.destination_nat/4` - Destination NAT
- `NAT.redirect_port/4` - Port redirection
- `NAT.port_forward/5` - Port forwarding
- `NAT.setup_masquerade/2` - Masquerading setup

**Usage:**
```elixir
alias NFTables.NAT

# Source NAT
:ok = NAT.source_nat(pid, "10.0.0.0/24", "203.0.113.1")

# Port forwarding
:ok = NAT.port_forward(pid, 8080, "10.0.0.10", 80)

# Masquerade
:ok = NAT.setup_masquerade(pid, out_interface: "eth0")
```

### Query Module - Firewall Inspection

**Purpose:** List tables, chains, rules, sets, elements.

**Key Functions:**
- `Query.list_tables/2` - List tables
- `Query.list_chains/3` - List chains
- `Query.list_rules/4` - List rules
- `Query.list_sets/3` - List sets
- `Query.list_set_elements/3` - List set elements

**Usage:**
```elixir
alias NFTables.Query

{:ok, tables} = Query.list_tables(pid, family: :inet)
{:ok, chains} = Query.list_chains(pid, family: :inet)
{:ok, rules} = Query.list_rules(pid, "filter", "INPUT", family: :inet)
```

---

## Convenience Aliases

The Match API provides **shorter function names** for common operations:

| Full Name | Alias | Example |
|-----------|-------|---------|
| `source_ip/2` | `source/2` | `source("192.168.1.1")` |
| `dest_ip/2` | `dest/2` | `dest("10.0.0.1")` |
| `source_port/2` | `sport/2` | `sport(1024)` |
| `dest_port/2` | `dport/2` | `dport(80)` |
| `dest_port/2` | `port/2` | `port(22)` |
| `ct_state/2` | `state/2` | `state([:established])` |
| `rate_limit/3` | `limit/3` | `limit(10, :minute)` |

**Example:**
```elixir
# Using full names
rule() |> source_ip("192.168.1.100") |> tcp() |> dport(22) |> rate_limit(10, :minute) |> accept()

# Using aliases (shorter, clearer)
rule() |> source("192.168.1.100") |> tcp() |> dport(22) |> limit(10, :minute) |> accept()
```

---

## Protocol Helpers

Quick protocol matching without full protocol/1 syntax:

| Helper | Equivalent | Usage |
|--------|-----------|-------|
| `tcp()` | `protocol(:tcp)` | `rule() \|> tcp() \|> dport(80)` |
| `udp()` | `protocol(:udp)` | `rule() \|> udp() \|> dport(53)` |
| `icmp()` | `protocol(:icmp)` | `rule() \|> icmp() \|> accept()` |

---

## Actions vs Verdicts

### Actions (Non-terminal)

Actions **do not stop rule evaluation**. Multiple actions can be chained.

| Action | Description | Example |
|--------|-------------|---------|
| `counter()` | Count packets | `rule() \|> counter() \|> accept()` |
| `log/2` | Log to syslog | `rule() \|> log("DROP: ") \|> drop()` |
| `limit/3` | Rate limiting | `rule() \|> limit(10, :minute) \|> accept()` |
| `set_mark/2` | Mark packets | `rule() \|> set_mark(42) \|> accept()` |

### Verdicts (Terminal)

Verdicts **stop rule evaluation**. Only one verdict per rule.

| Verdict | Description | Example |
|---------|-------------|---------|
| `accept()` | Accept packet | `rule() \|> tcp() \|> dport(80) \|> accept()` |
| `drop()` | Drop silently | `rule() \|> source("1.2.3.4") \|> drop()` |
| `reject/1` | Drop with ICMP | `rule() \|> reject(:tcp_reset)` |
| `jump/2` | Jump to chain | `rule() \|> jump("custom_chain")` |
| `return_from_chain/1` | Return from jump | `rule() \|> return_from_chain()` |

---

## Common Patterns

### Accept Established Connections

```elixir
expr = rule()
  |> state([:established, :related])
  |> accept()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

### SSH with Rate Limiting

```elixir
expr = rule()
  |> tcp()
  |> dport(22)
  |> state([:new])
  |> limit(10, :minute, burst: 5)
  |> log("SSH: ", level: :info)
  |> accept()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

### Block IP with Logging

```elixir
expr = rule()
  |> source("192.168.1.100")
  |> log("BLOCKED: ", level: :warn)
  |> drop()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

### Port Forwarding (DNAT)

```elixir
alias NFTables.NAT

# Forward external port 8080 to internal 10.0.0.10:80
:ok = NAT.port_forward(pid, 8080, "10.0.0.10", 80)
```

### NAT Gateway (Masquerade)

```elixir
expr = rule()
  |> oif("eth0")
  |> masquerade()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "nat", chain: "postrouting", family: :inet)
|> Executor.execute(pid)
```

### IP Blocklist with Sets

```elixir
# Match source IP against set
expr = rule()
  |> set("blocklist", :saddr)
  |> counter()
  |> log("BLOCKED_IP: ")
  |> drop()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)

# Add/remove IPs dynamically
:ok = NFTables.Set.add_elements(pid, "filter", "blocklist", :inet, ["1.2.3.4"])
:ok = NFTables.Set.delete_elements(pid, "filter", "blocklist", :inet, ["1.2.3.4"])
```

### SYN Proxy (DDoS Protection)

```elixir
expr = rule()
  |> tcp()
  |> dport(443)
  |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
  |> state([:new])
  |> synproxy(mss: 1460, wscale: 7, timestamp: true, sack_perm: true)
  |> accept()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

### Connection Limit

```elixir
expr = rule()
  |> tcp()
  |> dport(80)
  |> state([:new])
  |> limit_connections(100)
  |> drop()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

---

## Best Practices

### 1. Always Use Builder/Executor Pattern

**DO:**
```elixir
import NFTables.Match
alias NFTables.{Builder, Executor}

expr = rule() |> tcp() |> dport(22) |> accept() |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

**DON'T:**
```elixir
# Old API - No longer exists!
Match.new(pid, "filter", "INPUT")
|> Match.tcp()
|> Match.commit()  # This does not exist!
```

### 2. Use Convenience Aliases for Conciseness

**DO:**
```elixir
rule() |> tcp() |> dport(22) |> state([:new]) |> limit(10, :minute) |> accept()
```

**DON'T:**
```elixir
rule() |> protocol(:tcp) |> dport(22) |> ct_state([:new]) |> rate_limit(10, :minute) |> accept()
```

### 3. Use Protocol Helpers

**DO:**
```elixir
rule() |> tcp() |> dport(80) |> accept()
rule() |> udp() |> dport(53) |> accept()
rule() |> icmp() |> accept()
```

**DON'T:**
```elixir
rule() |> protocol(:tcp) |> dport(80) |> accept()
rule() |> protocol(:udp) |> dport(53) |> accept()
rule() |> protocol(:icmp) |> accept()
```

### 4. Always Call to_expr() Before Using with Builder

**DO:**
```elixir
expr = rule() |> tcp() |> dport(22) |> accept() |> to_expr()
Builder.new() |> Builder.add_rule(expr, ...)
```

**DON'T:**
```elixir
builder = rule() |> tcp() |> dport(22) |> accept()
Builder.new() |> Builder.add_rule(builder, ...)  # Wrong! Need to_expr() first
```

### 5. Use Policy Module for Common Patterns

**DO:**
```elixir
alias NFTables.Policy

:ok = Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)
```

**DON'T:**
```elixir
# Manually building all these rules when Policy can do it
rule() |> iif("lo") |> accept() |> to_expr() |> ...
rule() |> state([:established, :related]) |> accept() |> to_expr() |> ...
rule() |> state([:invalid]) |> drop() |> to_expr() |> ...
# ... etc
```

### 6. Import Match for Clean Syntax

**DO:**
```elixir
import NFTables.Match

rule() |> tcp() |> dport(22) |> accept()
```

**DON'T:**
```elixir
NFTables.Match.rule() |> NFTables.Match.tcp() |> NFTables.Match.dport(22) |> NFTables.Match.accept()
```

### 7. Use Atomic Multi-Command Operations with Builder

**DO:**
```elixir
alias NFTables.Builder

Builder.new(family: :inet)
|> Builder.add_table("filter")
|> Builder.add_chain("INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
|> Builder.set_table("filter")
|> Builder.set_chain("INPUT")
|> Builder.add_rule(expr1)
|> Builder.add_rule(expr2)
|> Builder.add_rule(expr3)
|> Builder.execute(pid)
```

**DON'T:**
```elixir
# Multiple separate execute calls (slower, non-atomic)
Builder.new() |> Builder.add_rule(expr1) |> Builder.execute(pid)
Builder.new() |> Builder.add_rule(expr2) |> Builder.execute(pid)
Builder.new() |> Builder.add_rule(expr3) |> Builder.execute(pid)
```

### 8. Use NAT Module for NAT Operations

**DO:**
```elixir
alias NFTables.NAT

:ok = NAT.port_forward(pid, 8080, "10.0.0.10", 80)
:ok = NAT.source_nat(pid, "10.0.0.0/24", "203.0.113.1")
```

**DON'T:**
```elixir
# Manually building NAT rules when NAT module provides helpers
rule() |> tcp() |> dport(8080) |> dnat_to("10.0.0.10", port: 80) |> ...
```

### 9. Use Query Module for Inspection

**DO:**
```elixir
alias NFTables.Query

{:ok, rules} = Query.list_rules(pid, "filter", "INPUT", family: :inet)
{:ok, tables} = Query.list_tables(pid, family: :inet)
```

**DON'T:**
```elixir
# Don't use old Rule.list or other deprecated query functions
Rule.list(pid, "filter", "INPUT")  # Old API - deprecated!
```

---

## Testing Principles

### Never Test with Live Network Tables

**DO:**
```elixir
# Use isolated test tables
table = "test_#{:rand.uniform(1_000_000)}"
:ok = NFTables.Table.add(pid, %{name: table, family: :inet})

# Test with isolated table
Builder.new()
|> Builder.add_rule(expr, table: table, chain: "INPUT", family: :inet)
|> Executor.execute(pid)

# Cleanup
:ok = NFTables.Table.delete(pid, table, :inet)
```

**DON'T:**
```elixir
# Don't hook to live tables like input, output, forward, nat
Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)  # Dangerous!
|> Executor.execute(pid)
```

### Test Expression Building Without Execution

```elixir
test "building SSH rule expression" do
  import NFTables.Match

  # Test pure expression building (no execution, no pid needed)
  expr = rule()
    |> tcp()
    |> dport(22)
    |> accept()
    |> to_expr()

  assert is_list(expr)
  assert length(expr) == 3
end
```

---

## Permission Guidelines

### No sudo Access Available

The test/development environment does **not have sudo access**. Always ask the user to run commands with sudo externally.

**DO:**
```elixir
# In your instructions or error messages
"Please run: sudo setcap cap_net_admin=ep priv/port_nftables"
"Please run: sudo nft list ruleset"
```

**DON'T:**
```elixir
# Don't try to run sudo commands in code
System.cmd("sudo", ["nft", "list", "ruleset"])  # Won't work!
```

---

## Distributed Firewall

### Build Commands Centrally, Execute Remotely

The Match API is designed for **distributed firewall architectures**:

```elixir
import NFTables.Match
alias NFTables.Builder

# Central C&C node - Build configuration
builder = Builder.new(family: :inet)
|> Builder.add_table("filter")
|> Builder.add_chain("INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
|> Builder.add_rule(
  rule() |> source("1.2.3.4") |> drop() |> to_expr()
)

# Convert to JSON for transport
json_cmd = Builder.to_json(builder)

# Send to remote firewall nodes
MyTransport.send_to_nodes(["fw-1", "fw-2", "fw-3"], json_cmd)

# On remote nodes - Execute received command
NFTables.Executor.execute(json_cmd, pid)
```

**Benefits:**
- **Centralized Policy** - Manage firewall rules from one location
- **Transport Agnostic** - Use any network transport (Phoenix PubSub, gRPC, etc.)
- **Minimal Remote Footprint** - Firewall nodes only need port + minimal shim

---

## Migration from Old API

### Old API (Removed)

The old execution-based Match API has been **completely removed**:

```elixir
# This no longer exists!
Match.new(pid, "filter", "INPUT")
|> Match.tcp()
|> Match.dport(22)
|> Match.commit()  # Does not exist!
```

### New API (Current)

The new pure functional Match API:

```elixir
import NFTables.Match
alias NFTables.{Builder, Executor}

expr = rule()
  |> tcp()
  |> dport(22)
  |> accept()
  |> to_expr()

Builder.new()
|> Builder.add_rule(expr, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)
```

**Key Changes:**
- `Match.new(pid, table, chain)` → `rule()`
- `Match.commit()` → `to_expr()` + `Builder.add_rule()` + `Executor.execute()`
- `Match.to_nft_command()` → `Builder.to_json()`
- Execution-coupled design → Pure functional, no side effects
- nft syntax strings → JSON expressions
- Immediate execution → Explicit execution via Executor

---

## Complete Example

```elixir
# Setup NFTables
{:ok, pid} = NFTables.start_link()

# Import for clean syntax
import NFTables.Match
alias NFTables.{Builder, Executor, Policy}

# Use Policy for common patterns
:ok = Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)

# Build custom rules
ssh_rule = rule()
  |> tcp()
  |> dport(22)
  |> state([:new])
  |> limit(10, :minute, burst: 5)
  |> log("SSH_NEW: ", level: :info)
  |> accept()
  |> to_expr()

block_rule = rule()
  |> source("192.168.1.100")
  |> log("BLOCKED_IP: ", level: :warn)
  |> drop()
  |> to_expr()

# Execute with Builder
Builder.new()
|> Builder.add_rule(ssh_rule, table: "filter", chain: "INPUT", family: :inet)
|> Builder.add_rule(block_rule, table: "filter", chain: "INPUT", family: :inet)
|> Executor.execute(pid)

# Manage IP blocklist
:ok = NFTables.Set.add_elements(pid, "filter", "blocklist", :inet, [
  "1.2.3.4",
  "5.6.7.8"
])

# Query existing rules
{:ok, rules} = NFTables.Query.list_rules(pid, "filter", "INPUT", family: :inet)
IO.inspect(rules, label: "Current Rules")
```

---

## Summary

### ✅ DO

- Use pure functional Match API
- Use Builder/Executor separation
- Use convenience aliases (tcp(), dport(), state(), limit())
- Use Protocol helpers (tcp(), udp(), icmp())
- Call to_expr() before using with Builder
- Use Policy module for common patterns
- Use NAT module for NAT operations
- Use Query module for inspection
- Test with isolated tables
- Import Match for clean syntax
- Use atomic multi-command operations with Builder

### ❌ DON'T

- Use old execution-based Match API (removed)
- Execute without Builder/Executor
- Test with live network tables (input, output, forward)
- Try to run sudo commands in code
- Forget to call to_expr()
- Manually build rules that Policy/NAT provide
- Use deprecated Rule.list, Rule.block_ip, etc.

---

## Additional Resources

- **Main README** - Complete API documentation
- **dev_docs/README.md** - Architecture and design
- **dev_docs/QUICK_REFERENCE.md** - Quick lookup guide
- **dev_docs/REFERENCE.md** - Comprehensive API reference
- **API_REFACTORING_COMPLETE.md** - Refactoring completion report
