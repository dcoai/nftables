# NFTex API Reference

Complete reference guide for the NFTex library.

## Table of Contents

1. [nftables Documentation & Mapping](#nftables-documentation--mapping)
2. [NFTex.Port - Port Management](#nftexport---port-management)
3. [NFTex.Table - Table Operations](#nftextable---table-operations)
4. [NFTex.Chain - Chain Operations](#nftexchain---chain-operations)
5. [NFTex.Rule - Rule Operations](#nftexrule---rule-operations)
6. [NFTex.RuleBuilder - Fluent Rule Construction](#nftexrulebuilder---fluent-rule-construction)
7. [NFTex.Set - Set Operations](#nftexset---set-operations)
8. [NFTex.Policy - Pre-built Policies](#nftexpolicy---pre-built-policies)
9. [NFTex.Sysctl - Kernel Parameter Management](#nftexsysctl---kernel-parameter-management)
10. [NFTex.Sysctl.Network - Network Helpers](#nftexsysctlnetwork---network-helpers)
11. [NFTex.Query - Query Operations](#nftexquery---query-operations)
12. [NFTex.NAT - NAT Operations](#nftexnat---nat-operations)
13. [NFTex.JSONBuilder - JSON Command Builder](#nftexjsonbuilder---json-command-builder)

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

### Mapping nftables Concepts to NFTex

#### Command Line → NFTex API

| nftables Command | NFTex Equivalent |
|-----------------|------------------|
| `nft add table inet filter` | `NFTex.Table.create(pid, %{name: "filter", family: :inet})` |
| `nft add chain inet filter input { type filter hook input priority 0; policy drop; }` | `NFTex.Chain.create(pid, %{table: "filter", name: "input", family: :inet, type: :filter, hook: :input, priority: 0, policy: :drop})` |
| `nft add rule inet filter input ip saddr 192.168.1.1 drop` | `NFTex.Rule.block_ip(pid, "filter", "input", "192.168.1.1")` |
| `nft add set inet filter blocklist { type ipv4_addr; }` | `NFTex.Set.create(pid, %{table: "filter", name: "blocklist", family: :inet, type: "ipv4_addr"})` |
| `nft add element inet filter blocklist { 192.168.1.1 }` | `NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ["192.168.1.1"])` |
| `nft list ruleset` | `NFTex.Query.list_rules(pid)` |
| `nft list tables` | `NFTex.Query.list_tables(pid)` |

#### nftables Syntax → RuleBuilder

| nftables Rule Syntax | NFTex RuleBuilder |
|---------------------|-------------------|
| `ip saddr 192.168.1.1` | `RuleBuilder.match_source_ip("192.168.1.1")` |
| `tcp dport 22` | `RuleBuilder.match_dest_port(22)` |
| `ct state established,related` | `RuleBuilder.match_ct_state([:established, :related])` |
| `iifname "eth0"` | `RuleBuilder.match_iif("eth0")` |
| `limit rate 10/minute` | `RuleBuilder.rate_limit(10, :minute)` |
| `counter` | `RuleBuilder.counter()` |
| `log prefix "DROPPED: "` | `RuleBuilder.log("DROPPED: ")` |
| `drop` | `RuleBuilder.drop()` |
| `accept` | `RuleBuilder.accept()` |
| `reject` | `RuleBuilder.reject()` |

#### Protocol Families

| nftables Family | NFTex Atom |
|----------------|-----------|
| `inet` | `:inet` |
| `ip` | `:inet` or `:ip` |
| `ip6` | `:inet6` or `:ip6` |
| `arp` | `:arp` |
| `bridge` | `:bridge` |
| `netdev` | `:netdev` |

#### Chain Types and Hooks

| nftables Type | NFTex Atom | Available Hooks |
|--------------|-----------|----------------|
| `filter` | `:filter` | `:prerouting`, `:input`, `:forward`, `:output`, `:postrouting` |
| `nat` | `:nat` | `:prerouting`, `:input`, `:output`, `:postrouting` |
| `route` | `:route` | `:output` |

#### Connection Tracking States

| nftables State | NFTex Atom |
|---------------|-----------|
| `new` | `:new` |
| `established` | `:established` |
| `related` | `:related` |
| `invalid` | `:invalid` |
| `untracked` | `:untracked` |

### JSON Format vs nft Syntax

NFTex uses a **hybrid approach**:

1. **JSON format** for structured operations (tables, chains, sets):
   ```elixir
   NFTex.Table.create(pid, %{name: "filter", family: :inet})
   # Generates: {"nftables": [{"add": {"table": {"family": "inet", "name": "filter"}}}]}
   ```

2. **nft syntax strings** for complex rules:
   ```elixir
   RuleBuilder.new(pid, "filter", "INPUT")
   |> RuleBuilder.match_source_ip("192.168.1.1")
   |> RuleBuilder.drop()
   # Generates: "add rule inet filter INPUT ip saddr 192.168.1.1 drop"
   ```

Both formats are processed by the same `libnftables.nft_run_cmd_from_buffer()` function.

---

## NFTex.Port - Port Management

Start and manage the NFTex port process.

### Functions

#### `start_link/1`

Start the NFTex port process.

```elixir
# Start with default options
{:ok, pid} = NFTex.start_link()

# Start with custom options
{:ok, pid} = NFTex.start_link(check_capabilities: false)
```

**Options:**
- `:check_capabilities` - Check for CAP_NET_ADMIN capability (default: `true`)

**Returns:** `{:ok, pid}` or `{:error, reason}`

#### `stop/1`

Stop the NFTex port process.

```elixir
:ok = NFTex.Port.stop(pid)
```

#### `call/2`

Send a raw command to the port.

```elixir
# JSON command
json = ~s({"nftables": [{"list": {"tables": {}}}]})
{:ok, response} = NFTex.Port.call(pid, json)

# nft syntax command
{:ok, response} = NFTex.Port.call(pid, "list tables")
```

**Note:** Most users should use higher-level APIs instead of calling this directly.

---

## NFTex.Table - Table Operations

Manage nftables tables.

### Functions

#### `create/2`

Create a new table.

```elixir
# Create inet table
:ok = NFTex.Table.create(pid, %{
  name: "filter",
  family: :inet
})

# Create ip6 table
:ok = NFTex.Table.create(pid, %{
  name: "filter6",
  family: :inet6
})
```

**Parameters:**
- `name` - Table name (string, required)
- `family` - Protocol family (atom, required)

#### `delete/3`

Delete a table.

```elixir
:ok = NFTex.Table.delete(pid, "filter", :inet)
```

#### `list/2`

List all tables.

```elixir
{:ok, tables} = NFTex.Table.list(pid, family: :inet)

for table <- tables do
  IO.puts("Table: #{table.name}")
end
```

#### `exists?/3`

Check if a table exists.

```elixir
if NFTex.Table.exists?(pid, "filter", :inet) do
  IO.puts("Table exists")
end
```

---

## NFTex.Chain - Chain Operations

Manage nftables chains.

### Functions

#### `create/2`

Create a new chain.

```elixir
# Create base chain (with hook)
:ok = NFTex.Chain.create(pid, %{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
})

# Create regular chain (no hook)
:ok = NFTex.Chain.create(pid, %{
  table: "filter",
  name: "custom_rules",
  family: :inet
})
```

**Base Chain Parameters:**
- `table` - Table name (string, required)
- `name` - Chain name (string, required)
- `family` - Protocol family (atom, required)
- `type` - Chain type (`:filter`, `:nat`, `:route`)
- `hook` - Hook point (`:prerouting`, `:input`, `:forward`, `:output`, `:postrouting`)
- `priority` - Chain priority (integer)
- `policy` - Default policy (`:accept` or `:drop`)

**Regular Chain Parameters:**
- `table` - Table name (string, required)
- `name` - Chain name (string, required)
- `family` - Protocol family (atom, required)

#### `delete/4`

Delete a chain.

```elixir
:ok = NFTex.Chain.delete(pid, "filter", "INPUT", :inet)
```

#### `list/2`

List all chains.

```elixir
{:ok, chains} = NFTex.Chain.list(pid, family: :inet)

for chain <- chains do
  IO.puts("Chain: #{chain.name} (table: #{chain.table})")
end
```

#### `exists?/4`

Check if a chain exists.

```elixir
if NFTex.Chain.exists?(pid, "filter", "INPUT", :inet) do
  IO.puts("Chain exists")
end
```

#### `set_policy/5`

Set chain policy.

```elixir
:ok = NFTex.Chain.set_policy(pid, "filter", "INPUT", :inet, :drop)
```

---

## NFTex.Rule - Rule Operations

Manage firewall rules.

### Functions

#### `block_ip/4`

Block an IP address.

```elixir
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", "192.168.1.100")
```

#### `accept_ip/4`

Accept an IP address.

```elixir
:ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", "10.0.0.1")
```

#### `add/5`

Add a rule with custom nft syntax.

```elixir
:ok = NFTex.Rule.add(pid, "filter", "INPUT", :inet, "tcp dport 80 accept")
```

#### `list/3`

List rules in a chain.

```elixir
{:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)

for rule <- rules do
  IO.inspect(rule)
end
```

#### `delete/5`

Delete a rule by handle.

```elixir
:ok = NFTex.Rule.delete(pid, "filter", "INPUT", :inet, 42)
```

---

## NFTex.RuleBuilder - Fluent Rule Construction

Build complex rules using a chainable API.

### Basic Usage

```elixir
alias NFTex.RuleBuilder

RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_source_ip("192.168.1.1")
|> RuleBuilder.drop()
|> RuleBuilder.commit()
```

### Match Functions

#### `match_source_ip/2`

Match source IP address.

```elixir
RuleBuilder.match_source_ip(builder, "192.168.1.1")
RuleBuilder.match_source_ip(builder, "10.0.0.0/8")
```

#### `match_dest_ip/2`

Match destination IP address.

```elixir
RuleBuilder.match_dest_ip(builder, "8.8.8.8")
```

#### `match_source_port/2`

Match source port.

```elixir
RuleBuilder.match_source_port(builder, 1024)
```

#### `match_dest_port/2`

Match destination port.

```elixir
RuleBuilder.match_dest_port(builder, 22)
RuleBuilder.match_dest_port(builder, 80)
```

#### `match_protocol/2`

Match protocol.

```elixir
RuleBuilder.match_protocol(builder, :tcp)
RuleBuilder.match_protocol(builder, :udp)
RuleBuilder.match_protocol(builder, :icmp)
```

#### `match_ct_state/2`

Match connection tracking state.

```elixir
RuleBuilder.match_ct_state(builder, [:established, :related])
RuleBuilder.match_ct_state(builder, [:new])
RuleBuilder.match_ct_state(builder, [:invalid])
```

#### `match_iif/2`

Match input interface.

```elixir
RuleBuilder.match_iif(builder, "eth0")
```

#### `match_oif/2`

Match output interface.

```elixir
RuleBuilder.match_oif(builder, "eth1")
```

### Action Functions

#### `counter/1`

Add packet/byte counter.

```elixir
RuleBuilder.counter(builder)
```

#### `log/2`

Log packets with prefix.

```elixir
RuleBuilder.log(builder, "DROPPED: ")
RuleBuilder.log(builder, "ACCEPTED SSH: ")
```

#### `rate_limit/3` or `rate_limit/4`

Rate limit packets.

```elixir
# Simple rate limit
RuleBuilder.rate_limit(builder, 10, :minute)

# With burst
RuleBuilder.rate_limit(builder, 10, :minute, burst: 20)
```

**Units:** `:second`, `:minute`, `:hour`, `:day`

### Verdict Functions

#### `accept/1`

Accept packets.

```elixir
RuleBuilder.accept(builder)
```

#### `drop/1`

Drop packets silently.

```elixir
RuleBuilder.drop(builder)
```

#### `reject/1` or `reject/2`

Reject packets with ICMP error.

```elixir
# Default reject
RuleBuilder.reject(builder)

# With specific rejection type
RuleBuilder.reject(builder, :icmp_port_unreachable)
RuleBuilder.reject(builder, :tcp_reset)
```

### Complete Examples

```elixir
# Rate-limited SSH
RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_dest_port(22)
|> RuleBuilder.rate_limit(10, :minute, burst: 20)
|> RuleBuilder.log("SSH: ")
|> RuleBuilder.counter()
|> RuleBuilder.accept()
|> RuleBuilder.commit()

# Block specific IP with logging
RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_source_ip("192.168.1.100")
|> RuleBuilder.log("BLOCKED IP: ")
|> RuleBuilder.drop()
|> RuleBuilder.commit()

# Allow established connections
RuleBuilder.new(pid, "filter", "INPUT")
|> RuleBuilder.match_ct_state([:established, :related])
|> RuleBuilder.accept()
|> RuleBuilder.commit()

# Interface-based rule
RuleBuilder.new(pid, "filter", "FORWARD")
|> RuleBuilder.match_iif("eth0")
|> RuleBuilder.match_oif("eth1")
|> RuleBuilder.match_ct_state([:established, :related])
|> RuleBuilder.accept()
|> RuleBuilder.commit()
```

---

## NFTex.Set - Set Operations

Manage nftables sets for efficient IP/port matching.

### Functions

#### `create/2`

Create a new set.

```elixir
:ok = NFTex.Set.create(pid, %{
  table: "filter",
  name: "blocklist",
  family: :inet,
  type: "ipv4_addr"
})

# With flags
:ok = NFTex.Set.create(pid, %{
  table: "filter",
  name: "interval_set",
  family: :inet,
  type: "ipv4_addr",
  flags: ["interval"]
})

# With timeout
:ok = NFTex.Set.create(pid, %{
  table: "filter",
  name: "temp_block",
  family: :inet,
  type: "ipv4_addr",
  timeout: 3600  # 1 hour
})
```

**Set Types:**
- `"ipv4_addr"` - IPv4 addresses
- `"ipv6_addr"` - IPv6 addresses
- `"ether_addr"` - Ethernet addresses
- `"inet_proto"` - Internet protocols
- `"inet_service"` - Internet services (ports)
- `"mark"` - Packet marks

**Flags:**
- `"constant"` - Set is constant (immutable)
- `"interval"` - Set contains intervals (ranges)
- `"timeout"` - Elements can have timeouts

#### `delete/4`

Delete a set.

```elixir
:ok = NFTex.Set.delete(pid, "filter", "blocklist", :inet)
```

#### `add_elements/5`

Add elements to a set.

```elixir
# Add single IP
:ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ["192.168.1.1"])

# Add multiple IPs
:ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, [
  "192.168.1.1",
  "192.168.1.2",
  "10.0.0.50"
])
```

#### `delete_elements/5`

Delete elements from a set.

```elixir
:ok = NFTex.Set.delete_elements(pid, "filter", "blocklist", :inet, ["192.168.1.1"])
```

#### `list_elements/3`

List elements in a set.

```elixir
{:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")

for elem <- elements do
  IO.puts("IP: #{elem.key_ip}")
end
```

#### `exists?/4`

Check if a set exists.

```elixir
if NFTex.Set.exists?(pid, "filter", "blocklist", :inet) do
  IO.puts("Set exists")
end
```

#### `list/2`

List all sets.

```elixir
{:ok, sets} = NFTex.Set.list(pid, family: :inet)

for set <- sets do
  IO.puts("Set: #{set.name} (type: #{set.type})")
end
```

---

## NFTex.Policy - Pre-built Policies

High-level firewall policy functions.

### Functions

#### `setup_basic_firewall/2`

Set up a complete basic firewall in one call.

```elixir
:ok = NFTex.Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)
```

**Options:**
- `:allow_services` - List of services to allow (`:ssh`, `:http`, `:https`, `:dns`)
- `:ssh_rate_limit` - SSH connections per minute (default: 10)
- `:http_rate_limit` - HTTP connections per minute (default: 100)

#### `accept_loopback/1`

Accept all loopback traffic.

```elixir
:ok = NFTex.Policy.accept_loopback(pid)
```

#### `accept_established/1`

Accept established and related connections.

```elixir
:ok = NFTex.Policy.accept_established(pid)
```

#### `drop_invalid/1`

Drop invalid packets.

```elixir
:ok = NFTex.Policy.drop_invalid(pid)
```

#### `allow_ssh/2`

Allow SSH with optional rate limiting.

```elixir
# Basic SSH allow
:ok = NFTex.Policy.allow_ssh(pid)

# With rate limiting
:ok = NFTex.Policy.allow_ssh(pid, rate_limit: 10, log: true)
```

#### `allow_http/2`

Allow HTTP traffic.

```elixir
:ok = NFTex.Policy.allow_http(pid)

# With rate limiting
:ok = NFTex.Policy.allow_http(pid, rate_limit: 100)
```

#### `allow_https/1`

Allow HTTPS traffic.

```elixir
:ok = NFTex.Policy.allow_https(pid)
```

#### `allow_dns/1`

Allow DNS traffic (TCP and UDP).

```elixir
:ok = NFTex.Policy.allow_dns(pid)
```

---

## NFTex.Sysctl - Kernel Parameter Management

Safely read and write kernel network parameters.

### Functions

#### `get/2`

Get a sysctl parameter value.

```elixir
{:ok, "0"} = NFTex.Sysctl.get(pid, "net.ipv4.ip_forward")
{:ok, "1"} = NFTex.Sysctl.get(pid, "net.ipv4.tcp_syncookies")
```

#### `set/3`

Set a sysctl parameter value.

```elixir
:ok = NFTex.Sysctl.set(pid, "net.ipv4.ip_forward", "1")
:ok = NFTex.Sysctl.set(pid, "net.ipv4.tcp_syncookies", "1")
```

#### `get!/2`

Get a sysctl parameter value, raising on error.

```elixir
value = NFTex.Sysctl.get!(pid, "net.ipv4.ip_forward")
```

#### `set!/3`

Set a sysctl parameter value, raising on error.

```elixir
:ok = NFTex.Sysctl.set!(pid, "net.ipv4.ip_forward", "1")
```

### Supported Parameters

**IPv4 Core:**
- `net.ipv4.ip_forward`
- `net.ipv4.conf.all.forwarding`
- `net.ipv4.conf.default.forwarding`

**IPv4 TCP:**
- `net.ipv4.tcp_syncookies`
- `net.ipv4.tcp_timestamps`
- `net.ipv4.tcp_tw_reuse`
- `net.ipv4.tcp_fin_timeout`
- `net.ipv4.tcp_keepalive_time`
- `net.ipv4.tcp_keepalive_probes`
- `net.ipv4.tcp_keepalive_intvl`
- `net.ipv4.ip_local_port_range` (format: "min max")

**IPv6:**
- `net.ipv6.conf.all.forwarding`
- `net.ipv6.conf.default.forwarding`

**Connection Tracking:**
- `net.netfilter.nf_conntrack_max`
- `net.netfilter.nf_conntrack_tcp_timeout_established`
- `net.netfilter.nf_conntrack_tcp_timeout_time_wait`
- `net.netfilter.nf_conntrack_tcp_timeout_close_wait`
- `net.netfilter.nf_conntrack_tcp_timeout_fin_wait`

**ICMP:**
- `net.ipv4.icmp_echo_ignore_all`
- `net.ipv4.icmp_echo_ignore_broadcasts`
- `net.ipv4.icmp_ratelimit`

**Security:**
- `net.ipv4.conf.all.rp_filter`
- `net.ipv4.conf.default.rp_filter`
- `net.ipv4.conf.all.accept_source_route`
- `net.ipv4.conf.default.accept_source_route`
- `net.ipv4.conf.all.send_redirects`
- `net.ipv4.conf.default.send_redirects`
- `net.ipv4.conf.all.accept_redirects`
- `net.ipv4.conf.default.accept_redirects`
- `net.ipv6.conf.all.accept_redirects`
- `net.ipv6.conf.default.accept_redirects`
- `net.ipv6.conf.all.accept_source_route`
- `net.ipv6.conf.default.accept_source_route`

---

## NFTex.Sysctl.Network - Network Helpers

High-level helpers for common sysctl operations.

### Functions

#### `enable_ipv4_forwarding/1`

Enable IPv4 forwarding.

```elixir
:ok = NFTex.Sysctl.Network.enable_ipv4_forwarding(pid)
```

#### `disable_ipv4_forwarding/1`

Disable IPv4 forwarding.

```elixir
:ok = NFTex.Sysctl.Network.disable_ipv4_forwarding(pid)
```

#### `ipv4_forwarding_enabled?/1`

Check if IPv4 forwarding is enabled.

```elixir
{:ok, true} = NFTex.Sysctl.Network.ipv4_forwarding_enabled?(pid)
```

#### `enable_ipv6_forwarding/1`

Enable IPv6 forwarding.

```elixir
:ok = NFTex.Sysctl.Network.enable_ipv6_forwarding(pid)
```

#### `disable_ipv6_forwarding/1`

Disable IPv6 forwarding.

```elixir
:ok = NFTex.Sysctl.Network.disable_ipv6_forwarding(pid)
```

#### `enable_syncookies/1`

Enable TCP SYN cookies (DDoS protection).

```elixir
:ok = NFTex.Sysctl.Network.enable_syncookies(pid)
```

#### `disable_syncookies/1`

Disable TCP SYN cookies.

```elixir
:ok = NFTex.Sysctl.Network.disable_syncookies(pid)
```

#### `set_conntrack_max/2`

Set maximum connection tracking entries.

```elixir
:ok = NFTex.Sysctl.Network.set_conntrack_max(pid, 131072)
```

#### `get_conntrack_max/1`

Get current connection tracking maximum.

```elixir
{:ok, 65536} = NFTex.Sysctl.Network.get_conntrack_max(pid)
```

#### `ignore_ping/1`

Ignore all ICMP ping requests (stealth mode).

```elixir
:ok = NFTex.Sysctl.Network.ignore_ping(pid)
```

#### `allow_ping/1`

Allow ICMP ping requests.

```elixir
:ok = NFTex.Sysctl.Network.allow_ping(pid)
```

#### `configure_router/2`

Configure common router settings.

```elixir
:ok = NFTex.Sysctl.Network.configure_router(pid,
  ipv4_forwarding: true,
  ipv6_forwarding: true,
  syncookies: true,
  send_redirects: false
)
```

**Options:**
- `:ipv4_forwarding` - Enable IPv4 forwarding (boolean)
- `:ipv6_forwarding` - Enable IPv6 forwarding (boolean)
- `:syncookies` - Enable SYN cookies (boolean)
- `:send_redirects` - Enable ICMP redirects (boolean)

#### `harden_security/1`

Apply security hardening settings.

```elixir
:ok = NFTex.Sysctl.Network.harden_security(pid)
```

**Settings Applied:**
- Enable reverse path filtering (anti-spoofing)
- Disable source routing
- Disable ICMP redirects
- Enable SYN cookies

---

## NFTex.Query - Query Operations

Query nftables configuration.

### Functions

#### `list_tables/2`

List all tables.

```elixir
{:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)

for table <- tables do
  IO.puts("Table: #{table.name} (family: #{table.family})")
end
```

#### `list_chains/2`

List all chains.

```elixir
{:ok, chains} = NFTex.Query.list_chains(pid, family: :inet)

for chain <- chains do
  IO.puts("Chain: #{chain.name} (table: #{chain.table})")
  if hook = Map.get(chain, :hook) do
    IO.puts("  Hook: #{hook}, Priority: #{chain.priority}, Policy: #{chain.policy}")
  end
end
```

#### `list_sets/2`

List all sets.

```elixir
{:ok, sets} = NFTex.Query.list_sets(pid, family: :inet)

for set <- sets do
  IO.puts("Set: #{set.name} (type: #{set.type})")
end
```

#### `list_rules/2`

List all rules.

```elixir
{:ok, rules} = NFTex.Query.list_rules(pid, family: :inet)

for rule <- rules do
  IO.inspect(rule)
end
```

#### `list_set_elements/3`

List elements in a specific set.

```elixir
{:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "blocklist")

for elem <- elements do
  IO.puts("Element: #{elem.key_ip}")
end
```

---

## NFTex.NAT - NAT Operations

Network Address Translation operations.

### Functions

#### `setup_masquerade/2`

Set up NAT with masquerading.

```elixir
:ok = NFTex.NAT.setup_masquerade(pid, %{
  table: "nat",
  out_interface: "eth0",
  masquerade_source: "10.0.0.0/24"
})
```

#### `add_port_forward/2`

Add port forwarding rule.

```elixir
:ok = NFTex.NAT.add_port_forward(pid, %{
  table: "nat",
  protocol: :tcp,
  external_port: 8080,
  internal_ip: "10.0.0.10",
  internal_port: 80
})
```

#### `add_dnat_rule/2`

Add destination NAT rule.

```elixir
:ok = NFTex.NAT.add_dnat_rule(pid, %{
  table: "nat",
  chain: "PREROUTING",
  protocol: :tcp,
  dest_port: 80,
  new_dest: "192.168.1.10:8080"
})
```

#### `add_snat_rule/2`

Add source NAT rule.

```elixir
:ok = NFTex.NAT.add_snat_rule(pid, %{
  table: "nat",
  chain: "POSTROUTING",
  source: "10.0.0.0/24",
  new_source: "203.0.113.1"
})
```

---

## NFTex.JSONBuilder - JSON Command Builder

Low-level JSON command construction (rarely needed by most users).

### Functions

#### `add_table/2`

Build add table JSON.

```elixir
cmd = NFTex.JSONBuilder.add_table("inet", "filter")
json = Jason.encode!(cmd)
```

#### `delete_table/2`

Build delete table JSON.

```elixir
cmd = NFTex.JSONBuilder.delete_table("inet", "filter")
```

#### `list_tables/1`

Build list tables JSON.

```elixir
cmd = NFTex.JSONBuilder.list_tables(family: :inet)
```

#### `add_chain/4`

Build add chain JSON.

```elixir
cmd = NFTex.JSONBuilder.add_chain("inet", "filter", "INPUT",
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)
```

#### `delete_chain/3`

Build delete chain JSON.

```elixir
cmd = NFTex.JSONBuilder.delete_chain("inet", "filter", "INPUT")
```

#### `add_set/4`

Build add set JSON.

```elixir
cmd = NFTex.JSONBuilder.add_set("inet", "filter", "blocklist",
  type: "ipv4_addr"
)
```

#### `delete_set/3`

Build delete set JSON.

```elixir
cmd = NFTex.JSONBuilder.delete_set("inet", "filter", "blocklist")
```

#### `add_element/4`

Build add element JSON.

```elixir
cmd = NFTex.JSONBuilder.add_element("inet", "filter", "blocklist",
  ["192.168.1.1", "192.168.1.2"]
)
```

#### `delete_element/4`

Build delete element JSON.

```elixir
cmd = NFTex.JSONBuilder.delete_element("inet", "filter", "blocklist",
  ["192.168.1.1"]
)
```

#### `add_rule/4`

Build add rule JSON.

```elixir
cmd = NFTex.JSONBuilder.add_rule("inet", "filter", "INPUT",
  "ip saddr 192.168.1.1 drop"
)
```

#### `delete_rule/4`

Build delete rule JSON.

```elixir
cmd = NFTex.JSONBuilder.delete_rule("inet", "filter", "INPUT", 42)
```

#### `list_ruleset/1`

Build list ruleset JSON.

```elixir
cmd = NFTex.JSONBuilder.list_ruleset(family: :inet)
```

#### `flush_ruleset/1`

Build flush ruleset JSON.

```elixir
cmd = NFTex.JSONBuilder.flush_ruleset(family: :inet)
```

#### `sysctl_get/1`

Build sysctl get JSON.

```elixir
json = NFTex.JSONBuilder.sysctl_get("net.ipv4.ip_forward")
```

#### `sysctl_set/2`

Build sysctl set JSON.

```elixir
json = NFTex.JSONBuilder.sysctl_set("net.ipv4.ip_forward", "1")
```

---

## Error Handling

All NFTex functions return either:
- `{:ok, result}` on success
- `{:error, reason}` on failure
- `:ok` for operations with no return value

**Example:**

```elixir
case NFTex.Table.create(pid, %{name: "filter", family: :inet}) do
  :ok ->
    IO.puts("Table created")

  {:error, reason} ->
    IO.puts("Failed: #{reason}")
end
```

**Bang versions (!)** raise on error:

```elixir
# Raises RuntimeError on failure
value = NFTex.Sysctl.get!(pid, "net.ipv4.ip_forward")
```

---

## See Also

- [Examples Directory](../examples/) - Complete working examples
- [Main README](../README.md) - Overview and quick start
- [Security Documentation](SECURITY.md) - Security considerations
- [Capabilities Documentation](CAPABILITIES.md) - Capability management
