# NFTex Examples

This directory contains practical examples demonstrating how to use NFTex for common nftables operations.

## Prerequisites

Before running these examples, ensure the NFTex port binary has the required capability:

```bash
sudo setcap cap_net_admin=ep priv/libnf_ex
```

Verify it's set correctly:

```bash
getcap priv/libnf_ex
# Should show: priv/libnf_ex = cap_net_admin+ep
```

## Running Examples

From the project root directory:

```bash
# Run a specific example
mix run examples/ip_blocklist.exs

# Or make executable and run directly
chmod +x examples/ip_blocklist.exs
./examples/ip_blocklist.exs
```

## Available Examples

### 1. IP Blocklist (`ip_blocklist.exs`)

Demonstrates how to create and manage an IP address blocklist using nftables sets.

**Topics covered:**
- Creating sets in the kernel
- Adding multiple IP addresses
- Listing blocked IPs
- Removing IPs from blocklist
- Checking if sets exist

**Use case:** Dynamic IP blocklisting for firewall applications

### 2. Query Tables (`query_tables.exs`)

Shows how to query and inspect your current nftables configuration.

**Topics covered:**
- Listing all tables
- Enumerating chains (base and regular)
- Viewing sets and their properties
- Listing rules
- Examining set elements

**Use case:** Auditing firewall configuration, building management dashboards

### 3. Firewall Rules (`firewall_rules.exs`)

Demonstrates creating dynamic firewall rules to block malicious IPs and allow trusted sources.

**Topics covered:**
- Using `NFTex.Rule.block_ip/4` for simple IP blocking
- Using `NFTex.Rule.accept_ip/4` for allowlist rules
- Listing rules with `NFTex.Rule.list/4`
- Automatic counter addition for traffic monitoring
- Dynamic rule creation without system restart

**Use case:** IDS integration, dynamic IP blocking, security incident response

## API Quick Reference

### NFTex.Rule - High-level rule operations

```elixir
{:ok, pid} = NFTex.start_link()

# Block an IP address
ip = <<192, 168, 1, 100>>
:ok = NFTex.Rule.block_ip(pid, "filter", "INPUT", ip)

# Accept an IP address
:ok = NFTex.Rule.accept_ip(pid, "filter", "INPUT", ip)

# List rules in a chain
{:ok, rules} = NFTex.Rule.list(pid, "filter", "INPUT", family: :inet)
```

### NFTex.Set - High-level set operations

```elixir
# Create a set (currently requires low-level API)
{:ok, pid} = NFTex.start_link()

# Add elements to existing set
ips = [<<192, 168, 1, 100>>, <<10, 0, 0, 50>>]
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

### NFTex.ExpressionBuilder - Low-level expression helpers

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

## Common Patterns

### IP Address Conversion

```elixir
# Convert IP address to binary
ip_binary = <<192, 168, 1, 100>>  # 192.168.1.100

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
sudo setcap cap_net_admin=ep priv/libnf_ex
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
