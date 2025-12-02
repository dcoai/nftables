# NFTables API Reference

Complete reference guide for the NFTables library.

## Advanced Features

NFTables includes comprehensive support for advanced nftables capabilities:

- **Flowtables** - Hardware-accelerated packet forwarding
- **Meters/Dynamic Sets** - Per-key rate limiting with composite keys
- **Raw Payload Matching** - Offset-based packet inspection for custom protocols
- **Socket Matching & TPROXY** - Transparent proxy support
- **SCTP/DCCP/GRE** - Specialized protocol matching
- **OSF (OS Fingerprinting)** - Passive OS detection

**Documentation:**
- [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) - Complete feature documentation with examples
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Quick examples of all features

---

## Table of Contents

1. [nftables Documentation & Mapping](#nftables-documentation--mapping)
2. [NFTables - Main Module](#nftables---main-module)
3. [NFTables.Builder - Unified Configuration Builder](#nftablesbuilder---unified-configuration-builder)
4. [NFTables.Expr - Pure Functional Rule Builder](#nftablesmatch---pure-functional-rule-builder)
5. [NFTables.Policy - Pre-built Policies](#nftablespolicy---pre-built-policies)
6. [NFTables.NAT - NAT Operations](#nftablesnat---nat-operations)
7. [NFTables.Sysctl - Kernel Parameter Management](#nftablessysctl---kernel-parameter-management)
8. [NFTables.Query - Query Operations](#nftablesquery---query-operations)
9. [NFTables.Local - Command Execution](#nftablesexecutor---command-execution)

---

## nftables Documentation & Mapping

### Official nftables Documentation

**Primary Resources:**
- **nftables Wiki**: https://wiki.nftables.org/
- **nftables Man Page**: `man nft` or https://manpages.debian.org/nft
- **JSON API Documentation**: https://wiki.nftables.org/wiki-nftables/index.php/JSON_API
- **Quick Reference**: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

**Community Resources:**
- Netfilter Project: https://www.netfilter.org/
- nftables on GitHub: https://github.com/google/nftables

### Mapping nftables Concepts to NFTables

#### Command Line → NFTables Builder API

| nftables Command | NFTables Equivalent |
|-----------------|------------------|
| `nft add table inet filter` | `Builder.new(family: :inet) \|> Builder.add(table: "filter") \|> Builder.submit(pid: pid)` |
| `nft add chain inet filter input { type filter hook input priority 0; policy drop; }` | `Builder.add(chain: "input", type: :filter, hook: :input, priority: 0, policy: :drop)` |
| `nft add rule inet filter input ip saddr 192.168.1.1 drop` | `Builder.add(rule: expr() \|> source_ip("192.168.1.1") \|> drop())` |
| `nft add set inet filter blocklist { type ipv4_addr; }` | `Builder.add(set: "blocklist", type: :ipv4_addr)` |
| `nft add element inet filter blocklist { 192.168.1.1 }` | `Builder.add(element: ["192.168.1.1"], set: "blocklist")` |
| `nft list ruleset` | `Query.list_ruleset() \|> Local.submit(pid: pid) \|> Decoder.decode()` |
| `nft list tables` | `Query.list_tables(family: :inet) \|> Local.submit(pid: pid)` |

#### nftables Syntax → Match API

| nftables Rule Syntax | NFTables Match |
|---------------------|-------------------|
| `ip saddr 192.168.1.1` | `expr() \|> source_ip("192.168.1.1")` |
| `tcp dport 22` | `expr() \|> tcp() \|> dport(22)` |
| `ct state established,related` | `expr() \|> ct_state([:established, :related])` |
| `iifname "eth0"` | `expr() \|> iif("eth0")` |
| `limit rate 10/minute` | `expr() \|> limit(10, :minute)` |
| `counter` | `expr() \|> counter()` |
| `log prefix "DROPPED: "` | `expr() \|> log("DROPPED: ")` |
| `drop` | `expr() \|> drop()` |
| `accept` | `expr() \|> accept()` |
| `reject` | `expr() \|> reject()` |

#### Protocol Families

| nftables Family | NFTables Atom |
|----------------|-----------|
| `inet` | `:inet` |
| `ip` | `:ip` |
| `ip6` | `:ip6` |
| `arp` | `:arp` |
| `bridge` | `:bridge` |
| `netdev` | `:netdev` |

#### Chain Types and Hooks

| nftables Type | NFTables Atom | Available Hooks |
|--------------|-----------|----------------|
| `filter` | `:filter` | `:prerouting`, `:input`, `:forward`, `:output`, `:postrouting` |
| `nat` | `:nat` | `:prerouting`, `:input`, `:output`, `:postrouting` |
| `route` | `:route` | `:output` |

#### Connection Tracking States

| nftables State | NFTables Atom |
|---------------|-----------|
| `new` | `:new` |
| `established` | `:established` |
| `related` | `:related` |
| `invalid` | `:invalid` |
| `untracked` | `:untracked` |

---

## NFTables - Main Module

The main entry point for starting the NFTables service.

### Functions

#### `start_link/1`

Start the NFTables service.

```elixir
# Start with default options
{:ok, pid} = NFTables.start_link()

# Start with custom options
{:ok, pid} = NFTables.start_link(check_capabilities: false)
```

**Options:**
- `:check_capabilities` - Check for CAP_NET_ADMIN capability (default: `true`)

**Returns:** `{:ok, pid}` or `{:error, reason}`

---

## NFTables.Builder - Unified Configuration Builder

The Builder module provides a unified, functional API for constructing nftables configurations.

### Design Philosophy

- **Pure Building** - Builder is immutable, no side effects during construction
- **Explicit Execution** - Commands execute only when `execute/2` is called
- **Context Tracking** - Automatically tracks table/chain context
- **Unified API** - Single set of functions for all object types
- **Auto-conversion** - Automatically converts Rule/Match structs to expression lists

### Basic Usage

```elixir
alias NFTables.Builder
import NFTables.Expr

{:ok, pid} = NFTables.start_link()

# Build and execute configuration
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(
  chain: "INPUT",
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)
|> Builder.add(rule: expr() |> tcp() |> dport(22) |> accept())
|> Builder.submit(pid: pid)
```

### Core Functions

#### `new/1`

Create a new builder.

```elixir
builder = Builder.new()
builder = Builder.new(family: :inet)
builder = Builder.new(family: :ip6)
```

#### `add/2`

Add an object (table, chain, rule, set, flowtable, etc.). The object type is automatically detected.

**Table:**
```elixir
Builder.add(builder, table: "filter")
Builder.add(builder, table: "nat", family: :inet)
```

**Chain:**
```elixir
# Base chain with hook
Builder.add(builder,
  chain: "INPUT",
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)

# Regular chain (no hook)
Builder.add(builder, chain: "custom_rules")
```

**Rule:**
```elixir
import NFTables.Expr

ssh_rule = expr() |> tcp() |> dport(22) |> accept()

Builder.add(builder, rule: ssh_rule)
Builder.add(builder, rule: ssh_rule, table: "filter", chain: "INPUT")
```

**Set:**
```elixir
# Simple set
Builder.add(builder,
  set: "blocklist",
  type: :ipv4_addr
)

# Dynamic set (for meters)
Builder.add(builder,
  set: "ratelimit",
  type: :ipv4_addr,
  flags: [:dynamic],
  timeout: 60,
  size: 10000
)
```

**Flowtable:**
```elixir
Builder.add(builder,
  flowtable: "fastpath",
  hook: :ingress,
  priority: 0,
  devices: ["eth0", "eth1"]
)
```

**Element:**
```elixir
Builder.add(builder,
  element: ["192.168.1.1", "192.168.1.2"],
  set: "blocklist"
)
```

#### `delete/2`

Delete an object.

```elixir
Builder.delete(builder, table: "filter")
Builder.delete(builder, chain: "INPUT")
Builder.delete(builder, set: "blocklist")
```

#### `flush/2`

Flush contents of an object.

```elixir
Builder.flush(builder, table: "filter")
Builder.flush(builder, chain: "INPUT")
Builder.flush(builder, [:all])  # Flush entire ruleset
```

#### `execute/2`

Execute the accumulated commands.

```elixir
result = Builder.submit(builder, pid: pid)
# Returns: :ok or {:error, reason}
```

#### `to_json/1`

Convert builder to JSON for inspection.

```elixir
json = Builder.to_json(builder)
IO.puts(json)
```

### Context Chaining

The builder automatically tracks context so you don't need to repeat table/chain names:

```elixir
Builder.new(family: :inet)
|> Builder.add(table: "filter", chain: "INPUT")
|> Builder.add(rule: expr() |> accept())  # Uses filter/INPUT
|> Builder.add(rule: expr() |> drop())    # Still uses filter/INPUT
```

---

## NFTables.Expr - Pure Functional Rule Builder

Build rule expressions using a pure functional, chainable API.

### Design Philosophy

- **Pure Functional** - No side effects, returns immutable structs
- **Chainable** - All functions return updated Match struct
- **Composable** - Build reusable rule fragments

### Basic Usage

```elixir
import NFTables.Expr

# Build a rule
ssh_rule = expr()
|> tcp()
|> dport(22)
|> ct_state([:new])
|> limit(10, :minute)
|> accept()

# Pass directly to Builder (no need for to_expr!)
Builder.add(builder, rule: ssh_rule)
```

### Core Functions

#### `rule/1`

Initialize a new rule.

```elixir
expr()
rule(family: :inet)
rule(family: :ip6)
```

### Protocol Matching

#### `tcp/1`

Match TCP protocol.

```elixir
expr() |> tcp() |> dport(80)
```

#### `udp/1`

Match UDP protocol.

```elixir
expr() |> udp() |> dport(53)
```

#### `icmp/1`, `icmpv6/1`

Match ICMP/ICMPv6.

```elixir
expr() |> icmp()
expr() |> icmpv6()
```

#### `sctp/1`, `dccp/1`, `gre/1`

Match specialized protocols.

```elixir
expr() |> sctp() |> dport(9899)
expr() |> dccp()
expr() |> gre()
```

### Address Matching

#### `source_ip/2`, `dest_ip/2`

Match IP addresses.

```elixir
expr() |> source_ip("192.168.1.1")
expr() |> source_ip("10.0.0.0/8")
expr() |> dest_ip("8.8.8.8")
```

#### `source_ip_set/2`, `dest_ip_set/2`

Match against IP sets.

```elixir
expr() |> source_ip_set("@blocklist")
expr() |> dest_ip_set("@allowlist")
```

### Port Matching

#### `sport/2`, `dport/2`

Match source/destination ports.

```elixir
# Single port
expr() |> tcp() |> dport(22)

# Port range
expr() |> tcp() |> dport(8000..9000)

# Multiple ports
expr() |> tcp() |> dport([22, 80, 443])
```

### Connection Tracking

#### `ct_state/2`

Match connection tracking state.

```elixir
expr() |> ct_state([:established, :related])
expr() |> ct_state([:new])
expr() |> ct_state([:invalid])
```

### Interface Matching

#### `iif/2`, `oif/2`

Match input/output interface.

```elixir
expr() |> iif("eth0")
expr() |> oif("eth1")
```

### Rate Limiting

#### `limit/3`, `limit/4`

Global rate limiting.

```elixir
expr() |> limit(10, :minute)
expr() |> limit(100, :second, burst: 200)
```

Units: `:second`, `:minute`, `:hour`, `:day`

### Meters (Per-Key Rate Limiting)

#### `meter_update/5`

Per-key rate limiting using dynamic sets.

```elixir
import NFTables.Expr.Meter

expr()
|> tcp()
|> dport(22)
|> meter_update(
  Meter.payload(:ip, :saddr),  # Track by source IP
  "ssh_limits",                 # Set name
  10,                           # Rate
  :minute,                      # Unit
  burst: 20                     # Optional burst
)
|> accept()
```

### Raw Payload Matching

#### `payload_raw/5`

Match packet data at specific offset.

```elixir
# Match DNS port at transport header offset 16
expr()
|> udp()
|> payload_raw(:th, 16, 16, 53)

# Match HTTP GET in inner header
expr()
|> tcp()
|> payload_raw(:ih, 0, 32, "GET ")
```

Bases: `:ll` (link layer), `:nh` (network header), `:th` (transport header), `:ih` (inner header)

#### `payload_raw_masked/6`

Match with bitmask.

```elixir
# Match TCP SYN flag
expr()
|> tcp()
|> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
```

### Logging

#### `log/2`, `log/3`

Log matching packets.

```elixir
expr() |> log("Dropped: ")
expr() |> log("SSH: ", level: "info")
```

### Counters

#### `counter/1`

Add packet/byte counter.

```elixir
expr() |> counter()
```

### Verdicts

#### `accept/1`

Accept packets.

```elixir
expr() |> accept()
```

#### `drop/1`

Drop packets silently.

```elixir
expr() |> drop()
```

#### `reject/1`, `reject/2`

Reject with ICMP error.

```elixir
expr() |> reject()
expr() |> reject(:tcp_reset)
expr() |> reject(:icmp_port_unreachable)
```

### NAT Actions

#### `snat/2`, `dnat/2`, `masquerade/1`

Network address translation.

```elixir
expr() |> snat("203.0.113.1")
expr() |> dnat("192.168.1.10:8080")
expr() |> masquerade()
```

### Advanced Features

#### `osf_name/2`, `osf_name/3`

OS fingerprinting.

```elixir
expr() |> osf_name("Linux")
expr() |> osf_name("Windows", ttl: :strict)
```

#### `socket_uid/2`, `socket_gid/2`

Match by socket owner.

```elixir
expr() |> socket_uid(1000)
expr() |> socket_gid(100)
```

### Complete Examples

```elixir
import NFTables.Expr
alias NFTables.Builder

# SSH with rate limiting
ssh_rule = expr()
|> tcp()
|> dport(22)
|> ct_state([:new])
|> limit(10, :minute, burst: 20)
|> log("SSH: ")
|> accept()

# Established connections
established_rule = expr()
|> ct_state([:established, :related])
|> accept()

# Block specific IP
block_rule = expr()
|> source_ip("192.168.1.100")
|> log("Blocked: ")
|> drop()

# Build and execute
Builder.new(family: :inet)
|> Builder.add(table: "filter", chain: "INPUT")
|> Builder.add(rule: established_rule)
|> Builder.add(rule: ssh_rule)
|> Builder.add(rule: block_rule)
|> Builder.submit(pid: pid)
```

---

## NFTables.Policy - Pre-built Policies

High-level firewall policy functions for common scenarios.  This is
primarily an example which shows how primitives can be used to build
more complex operations.  This can be used to help ensure there are
more consistent implementation of rules across a number of scenarios.

### Functions

#### `setup_basic_firewall/2`

Set up complete basic firewall.

```elixir
NFTables.Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)
```

#### `accept_loopback/1`

Accept all loopback traffic.

```elixir
NFTables.Policy.accept_loopback(pid)
```

#### `accept_established/1`

Accept established and related connections.

```elixir
NFTables.Policy.accept_established(pid)
```

#### `drop_invalid/1`

Drop invalid packets.

```elixir
NFTables.Policy.drop_invalid(pid)
```

#### `allow_ssh/2`

Allow SSH with optional rate limiting.

```elixir
NFTables.Policy.allow_ssh(pid)
NFTables.Policy.allow_ssh(pid, rate_limit: 10, log: true)
```

#### `allow_http/2`, `allow_https/1`, `allow_dns/1`

Allow web and DNS services.

```elixir
NFTables.Policy.allow_http(pid)
NFTables.Policy.allow_https(pid)
NFTables.Policy.allow_dns(pid)
```

---

## NFTables.NAT - NAT Operations

Network address translation helpers.

### Functions

#### `setup_masquerade/2`

Set up NAT with masquerading.

```elixir
NFTables.NAT.setup_masquerade(pid,
  out_interface: "eth0",
  source_network: "10.0.0.0/24"
)
```

#### `add_port_forward/2`

Add port forwarding rule.

```elixir
NFTables.NAT.add_port_forward(pid,
  protocol: :tcp,
  external_port: 8080,
  internal_ip: "10.0.0.10",
  internal_port: 80
)
```

---

## NFTables.Sysctl - Kernel Parameter Management

Safely read and write kernel network parameters.

### Functions

#### `get/2`, `set/3`

Get/set sysctl parameters.

```elixir
{:ok, "0"} = NFTables.Sysctl.get(pid, "net.ipv4.ip_forward")
:ok = NFTables.Sysctl.set(pid, "net.ipv4.ip_forward", "1")
```

#### `get!/2`, `set!/3`

Bang versions that raise on error.

```elixir
value = NFTables.Sysctl.get!(pid, "net.ipv4.ip_forward")
:ok = NFTables.Sysctl.set!(pid, "net.ipv4.ip_forward", "1")
```

### Common Parameters

**IPv4:**
- `net.ipv4.ip_forward` - Enable IP forwarding
- `net.ipv4.tcp_syncookies` - SYN cookie protection
- `net.ipv4.conf.all.rp_filter` - Reverse path filtering

**IPv6:**
- `net.ipv6.conf.all.forwarding` - Enable IPv6 forwarding

**Connection Tracking:**
- `net.netfilter.nf_conntrack_max` - Maximum tracked connections

See [lib/nftables/sysctl.ex](../lib/nftables/sysctl.ex) for complete list.

---

## NFTables.Query - Query Operations

Query current nftables configuration.

### Functions

#### `list_tables/1`, `list_chains/1`, `list_sets/1`, `list_rules/1`

List objects. All return query builders that need to be executed.

```elixir
alias NFTables.{Query, Local, Requestor, Decoder}

# List tables
{:ok, tables} = Query.list_tables(family: :inet)
  |> Local.submit(pid: pid)
  |> Decoder.decode()

# List chains
{:ok, chains} = Query.list_chains(family: :inet)
  |> Local.submit(pid: pid)
  |> Decoder.decode()

# List all rules
{:ok, rules} = Query.list_ruleset(family: :inet)
  |> Local.submit(pid: pid)
  |> Decoder.decode()
```

---

## NFTables.Local - Command Execution

Low-level command execution (most users won't need this directly).

### Functions

#### `execute/2`

Execute a command map or query.

```elixir
command = %{nftables: [%{add: %{table: %{family: "inet", name: "filter"}}}]}
{:ok, response} = NFTables.Local.submit(command, pid: pid)
```

---

## Error Handling

All NFTables functions return either:
- `{:ok, result}` on success
- `{:error, reason}` on failure
- `:ok` for operations with no return value

**Example:**

```elixir
case Builder.submit(builder, pid: pid) do
  :ok ->
    IO.puts("Configuration applied")

  {:error, reason} ->
    IO.puts("Failed: #{reason}")
end
```

**Bang versions (!)** raise on error:

```elixir
# Raises RuntimeError on failure
value = NFTables.Sysctl.get!(pid, "net.ipv4.ip_forward")
```

---

## See Also

- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Quick reference guide
- [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) - Advanced features documentation
- [Main README](../README.md) - Overview and quick start
- [Examples Directory](../examples/) - Complete working examples
