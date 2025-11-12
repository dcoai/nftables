# NFTex Examples

This directory contains practical examples demonstrating how to use NFTex for common nftables operations.

## Prerequisites

Before running these examples, ensure the NFTex port binary has the required capability:

```bash
sudo setcap cap_net_admin=ep priv/port_nftables
```

Verify it's set correctly:

```bash
getcap priv/port_nftables
# Should show: priv/port_nftables = cap_net_admin+ep
```

## Running Examples

From the project root directory:

```bash
# Run examples in order (recommended for first-time setup)
mix run examples/01_sysctl_management.exs
mix run examples/02_basic_firewall.exs
mix run examples/03_firewall_rules.exs
# ... etc

# Or run a specific example
mix run examples/04_ip_blocklist.exs

# Or make executable and run directly
chmod +x examples/04_ip_blocklist.exs
./examples/04_ip_blocklist.exs
```

## Available Examples

### Current API Examples (v0.4.0+)

These examples use the current JSON-based API (libnftables) and are ordered in the logical sequence for setting up a complete firewall from scratch:

#### 1. Sysctl Management (`01_sysctl_management.exs`)

**First Step:** Configure kernel network parameters before setting up firewall rules.

Demonstrates safe management of Linux kernel network parameters via NFTex's sysctl API.

**Topics covered:**
- Reading current network parameters (IPv4/IPv6 forwarding, TCP settings, etc.)
- Writing network parameters with validation
- High-level helpers (`Network.enable_ipv4_forwarding/1`, etc.)
- Composite operations (`configure_router/2`, `harden_security/1`)
- Parameter whitelist security
- Value validation and restoration

**Use case:** Router/gateway configuration, security hardening, network optimization, connection tracking tuning

#### 2. Basic Firewall (`02_basic_firewall.exs`)

**Second Step:** Set up the foundational firewall structure with secure defaults.

Complete secure firewall setup with defense-in-depth approach.

**Topics covered:**
- Default DROP policy
- Loopback traffic acceptance
- Established/related connection tracking
- Invalid packet dropping
- SSH rate limiting
- High-level Policy module usage

**Use case:** Secure server baseline, VPS hardening

#### 3. Firewall Rules (`03_firewall_rules.exs`)

**Third Step:** Add specific allow/block rules for trusted or malicious IPs.

Demonstrates creating dynamic firewall rules to block malicious IPs and allow trusted sources.

**Topics covered:**
- Using `NFTex.Rule.block_ip/4` for simple IP blocking
- Using `NFTex.Rule.accept_ip/4` for allowlist rules
- Listing rules with `NFTex.Rule.list/4`
- Automatic counter addition for traffic monitoring
- Dynamic rule creation without system restart

**Use case:** IDS integration, dynamic IP blocking, security incident response

#### 4. IP Blocklist (`04_ip_blocklist.exs`)

**Fourth Step:** Set up efficient dynamic IP blocking using nftables sets.

Demonstrates how to create and manage an IP address blocklist using nftables sets.

**Topics covered:**
- Creating sets in the kernel
- Adding multiple IP addresses (string format)
- Listing blocked IPs
- Removing IPs from blocklist
- Checking if sets exist

**Use case:** Dynamic IP blocklisting for firewall applications

#### 5. Rate Limiting (`05_rate_limiting.exs`)

**Fifth Step:** Add DDoS protection through rate limiting.

DDoS protection and resource management through rate limiting.

**Topics covered:**
- Per-service rate limits (SSH, HTTP, ICMP)
- New connection rate limiting
- Burst handling
- SYN flood protection
- Match API usage

**Use case:** Public-facing servers, API endpoints, DDoS mitigation

#### 6. Query Tables (`06_query_tables.exs`)

**Sixth Step:** Query and inspect your firewall configuration.

Shows how to query and inspect your current nftables configuration.

**Topics covered:**
- Listing all tables
- Enumerating chains (base and regular)
- Viewing sets and their properties
- Listing rules
- Examining set elements

**Use case:** Auditing firewall configuration, building management dashboards

### Future Examples

Additional examples for advanced features are planned:

- NAT Gateway and port forwarding
- Anti-spoofing with FIB expressions
- Advanced logging configurations
- Load balancing with DNAT

These will be implemented using the current v0.4.0 API (`JSONBuilder` with nft syntax strings).

## API Quick Reference

### NFTex.Policy - Pre-built Firewall Policies (New in 0.3.0)

High-level functions for common firewall configurations:

```elixir
{:ok, pid} = NFTex.start_link()

# Quick setup: Complete basic firewall in one call
:ok = NFTex.Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)

# Individual policies
:ok = NFTex.Policy.accept_loopback(pid)
:ok = NFTex.Policy.accept_established(pid)
:ok = NFTex.Policy.drop_invalid(pid)

# Service-specific allows
:ok = NFTex.Policy.allow_ssh(pid, rate_limit: 10, log: true)
:ok = NFTex.Policy.allow_http(pid, rate_limit: 100)
:ok = NFTex.Policy.allow_https(pid)
:ok = NFTex.Policy.allow_dns(pid)
```

### NFTex.Match - Fluent API for Rules

Chainable API for building complex rules intuitively:

```elixir
alias NFTex.Match

# Block IP with logging
Match.new(pid, "filter", "INPUT")
|> Match.source_ip("192.168.1.100")
|> Match.log("BLOCKED: ")
|> Match.drop()
|> Match.commit()

# Rate-limited SSH
Match.new(pid, "filter", "INPUT")
|> Match.dest_port(22)
|> Match.rate_limit(10, :minute, burst: 20)
|> Match.counter()
|> Match.accept()
|> Match.commit()

# Match established connections
Match.new(pid, "filter", "INPUT")
|> Match.ct_state([:established, :related])
|> Match.accept()
|> Match.commit()

# Interface-specific rules
Match.new(pid, "filter", "INPUT")
|> Match.iif("eth0")
|> Match.source_ip("10.0.0.0")
|> Match.reject(:icmp_port_unreachable)
|> Match.commit()
```

**Available match functions:**
- `match_source_ip/2` - Match source IP address
- `match_dest_ip/2` - Match destination IP address
- `match_source_port/2` - Match source port
- `match_dest_port/2` - Match destination port
- `match_ct_state/2` - Match connection tracking state (`:established`, `:related`, `:new`, `:invalid`)
- `match_iif/2` - Match input interface
- `match_oif/2` - Match output interface

**Available action functions:**
- `counter/1` - Add packet/byte counter
- `log/2` - Log packets with prefix
- `rate_limit/3` - Rate limit (rate, unit, opts)

**Available verdict functions:**
- `accept/1` - Accept packets
- `drop/1` - Drop packets silently
- `reject/1` - Reject with ICMP error

### NFTex.Chain - Chain Management (New in 0.3.0)

High-level chain operations with automatic resource management:

```elixir
# Create base chain (hooked into netfilter)
:ok = NFTex.Chain.add(pid, %{
  table: "filter",
  name: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
})

# Create regular chain (for organizing rules)
:ok = NFTex.Chain.add(pid, %{
  table: "filter",
  name: "my_custom_rules",
  family: :inet
})

# List all chains
{:ok, chains} = NFTex.Chain.list(pid, family: :inet)

# Check if chain exists
if NFTex.Chain.exists?(pid, "filter", "INPUT", :inet) do
  IO.puts("Chain exists")
end

# Set chain policy
:ok = NFTex.Chain.set_policy(pid, "filter", "INPUT", :inet, :drop)

# Delete chain
:ok = NFTex.Chain.delete(pid, "filter", "INPUT", :inet)
```

### NFTex.Rule - High-level rule operations

```elixir
{:ok, pid} = NFTex.start_link()

# Block an IP address
ip = "192.168.1.100"
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

# Accept an IP address
:ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", ip)

# List rules in a chain
{:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)
```

### NFTex.Set - High-level set operations

```elixir
{:ok, pid} = NFTex.start_link()

# Add elements to existing set (string format)
ips = ["192.168.1.100", "10.0.0.50"]
:ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ips)

# Delete elements
:ok = NFTex.Set.delete_elements(pid, "filter", "blocklist", :inet, ips)

# List elements
{:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")

# Check if set exists
exists = NFTex.Set.exists?(pid, "filter", "blocklist", :inet)

# List all sets
{:ok, sets} = NFTex.Set.list(pid, family: :inet)
```


### NFTex.Query - Query operations

```elixir
{:ok, pid} = NFTex.start_link()

# List tables
{:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)

# List chains
{:ok, chains} = NFTex.Query.list_chains(pid, family: :inet)

# List sets
{:ok, sets} = NFTex.Query.list_sets(pid, family: :inet)

# List rules
{:ok, rules} = NFTex.Query.list_rules(pid, family: :inet)

# List set elements
{:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "blocklist")
```

### NFTex.Sysctl - Network Parameter Management (New in 0.5.0)

Safe, whitelist-based access to kernel network parameters:

```elixir
alias NFTex.{Sysctl, Sysctl.Network}

{:ok, pid} = NFTex.start_link()

# Low-level API - Direct parameter access
{:ok, "0"} = Sysctl.get(pid, "net.ipv4.ip_forward")
:ok = Sysctl.set(pid, "net.ipv4.ip_forward", "1")

# High-level helpers for common operations
:ok = Network.enable_ipv4_forwarding(pid)
:ok = Network.enable_ipv6_forwarding(pid)
:ok = Network.enable_syncookies(pid)

# Check status
{:ok, true} = Network.ipv4_forwarding_enabled?(pid)

# Connection tracking
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
- 44 whitelisted network parameters only
- Value validation per parameter type
- Limited to `/proc/sys/net/*`
- Uses existing CAP_NET_ADMIN capability

**Supported Parameter Categories:**
- IPv4/IPv6 forwarding and configuration
- TCP settings (syncookies, timestamps, keepalive, port ranges)
- Connection tracking (nf_conntrack_max, timeouts)
- ICMP settings (echo ignore, rate limits)
- Security parameters (rp_filter, source routing, ICMP redirects)

## Common Patterns

### IP Address Format

```elixir
# Use string format for IP addresses (v0.4.0+)
ip = "192.168.1.100"
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

# NFTex.Query automatically converts hex keys to readable IPs
{:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")
for elem <- elements do
  IO.puts(elem.key_ip)  # "192.168.1.100"
end
```

### Error Handling

```elixir
case NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ips) do
  :ok ->
    IO.puts("IPs blocked successfully")

  {:error, reason} ->
    IO.puts("Failed to block IPs: #{reason}")
end
```

### Protocol Families

```elixir
:inet    # IPv4 (2)
:inet6   # IPv6 (10)
:ip      # IPv4 (alias for :inet)
:ip6     # IPv6 (alias for :inet6)
:arp     # ARP (3)
:bridge  # Bridge (7)
:netdev  # Netdev (5)
```

## Integration with nftables Rules

After creating a set with NFTex, use it in nftables rules:

```bash
# Block IPs in the blocklist
nft add rule filter input ip saddr @banned_ips drop

# Allow only whitelisted IPs
nft add rule filter input ip saddr @allowed_ips accept
nft add rule filter input drop
```

## Troubleshooting

### "Operation not permitted"

Ensure CAP_NET_ADMIN capability is set:
```bash
sudo setcap cap_net_admin=ep priv/port_nftables
```

### "Set not found"

Create the set first using the low-level API or `nft` command:
```bash
nft add set filter blocklist { type ipv4_addr\; }
```

### "Port failed to start"

Rebuild the native code:
```bash
cd native && zig build && cd ..
```

## Next Steps

- Read the module documentation: `h NFTex.Set` and `h NFTex.Query`
- Explore the test files in `/tmp/test_*.exs` for more examples
- Check out the main project README for advanced usage
