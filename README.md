# NFTables - Elixir Interface to nftables

Elixir module for Linux nftables. NFTables provides both high-level helper functions for common firewall operations and flexible rule building with composable functions.

## Quickstart Guide

### Installation

Add `nftables_port` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:nftables, "~> 0.6.1"}
  ]
end
```

Run the commands
```bash
mix deps.get
mix compile
```

### Setting Capabilities

The port executable requires `CAP_NET_ADMIN` to communicate with the kernel firewall:

```bash
# After compilation
sudo setcap cap_net_admin=ep deps/nftables_port/priv/port_nftables
chmod 700 deps/nftables_port/priv/port_nftables
```

### Build a Rule

**Note** - before running the following on a remote machine, be aware you are able block your remote access.  You may want to start by experimenting in a VM or local machine.

```elixir
alias NFTables.Builder
import NFTables.Expr

{:ok, pid} = NFTables.start_link()

def ssh(rule), do: rule |> tcp() |> dport(22)

response =
  Builder.new()
  |> Builder.add(table: "filter", family: :inet)
  |> Builder.add(chain: "INPUT", hook: :input)
  |> Builder.add(rule: expr() |> ssh() |> accept())
  |> Builder.commit(pid: pid)

IO.inspect(response}
```

## Features

- **High-Level APIs** - Simple functions for blocking IPs, managing sets, creating rules
- **Pure Functional Expr API** - Clean, composable expression builder with no side effects
- **Sysctl Management** - Read/Write access to network kernel parameters
- **Command/Execution Separation** - Build JSON/nft commands without executing
- **Batch Operations** - Atomic multi-command execution
- **IP Blocklist Management** - Add/remove IPs from blocklists with one function call
- **Query Operations** - List tables, chains, rules, sets, and elements
- **Builder Pattern** - Clear separation between building and executing commands
- **Policy Module** - Pre-built firewall policies (SSH, HTTP, rate limiting, etc.)
- **Elixir Port-based Architecture** - Fault isolation (crashes don't affect BEAM VM)
- **Security** - Port runs with minimal privileges (CAP_NET_ADMIN only)

## Advanced Features

NFTables includes comprehensive support for advanced nftables capabilities:

### Hardware Acceleration & Performance
- **Flowtables** - Hardware-accelerated packet forwarding for established connections
- **Meters/Dynamic Sets** - Per-key rate limiting with composite key support

### Deep Packet Inspection
- **Raw Payload Matching** - Offset-based packet header access for custom protocols
- **Socket Matching & TPROXY** - Transparent proxy support without destination changes

### Specialized Protocols
- **SCTP** - Stream Control Transmission Protocol (WebRTC, telephony)
- **DCCP** - Datagram Congestion Control Protocol (streaming, gaming)
- **GRE** - Generic Routing Encapsulation (VPN tunnels)

### Security & Intelligence
- **OSF (OS Fingerprinting)** - Passive operating system detection via TCP SYN analysis

See [dev_docs/ADVANCED_FEATURES.md](dev_docs/ADVANCED_FEATURES.md) for comprehensive documentation of all advanced features.

### NFTables_Port 

NFTables.Port is an elixir wrapper, and a program written in Zig which accepts json structures and sends them to NFTables using the libnftables (C library).  The Elixir part manages the Zig program as a Port.

```elixir
{:ok, pid} = NFTables.Port.start_link()

# Send JSON commands (for structured operations)
json_cmd = ~s({"nftables": [{"list": {"tables": {}}}]})
{:ok, json_response} = NFTables.Port.call(pid, json_cmd)
```

Visit the [NFTables.Port](https://github.com/dcoai/nftables_port) project page for details.  Take some time to review the [Security](https://github.com/dcoai/nftables_port/dev_docs/security.md) document found there.

### NFTables

NFTables.Port takes JSON requests and passes them on to nftables.  The Elixir NFTables library is a set of tools to query and build rule sets which can be applied via NFTables.Port.

is an Elixir library, which builds expressions (as Elixir Maps), which can be converted to JSON and passed to the NFTables_Port for processing by libnftables.  This library allows for constructing Tables, Chains, Sets, Rules, etc... in a composable elixer way

**Generate JSON using NFTables library**

```elixir
json =
  Builder.new()
  |> Builder.add(table: "filter", family: :inet)
  |> Builder.add(chain: "INPUT", hook: :input, policy: :drop)
  |> Builder.add(rule: tcp() |> dport(22) |> accept())
  |> Builder.to_json()
```

**Putting these together**

```elixir
{:ok, pid} = NFTables.Port.start_link()

json_cmd =
  Builder.new()
  |> Builder.add(table: "filter", family: :inet)
  |> Builder.add(chain: "INPUT", hook: :input, policy: :drop)
  |> Builder.add(rule: tcp() |> dport(22) |> accept())
  |> Builder.to_json()

{:ok, json_response} = NFTables.Port.call(pid, json_cmd)
```

Using this we can manage a local firewall from Elixir.

It would be possible to put the NFTables.Port portion on another node or multiple nodes, and use erlang's ssh module to build a secure communication layer to manage firewalls remotely, or to set up a distributed firewall.

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

## Potential Use Cases

- **Dynamic Firewall Management** - Modify firewall rules from your Elixir application
- **Local Firewall** - powered by Elixir
- **Distributed Firewall** - manage many firewalls centrally

### Security considerations

Once port_nftables has CAP_NET_ADMIN capability set, it can be used to set network related parameters (like enable ip_forwarding) and
configure nftables (create/delete/update tables, chains, rules, etc...).  Considering this it would be wise to protect this executable.

the `nftables_port` executable should fail to run if it has any `rwx` permissions for `other`.  if this is the case you will see a message similar to:

```
    \\
    \\SECURITY ERROR: Executable has world permissions enabled!
    \\
    \\Current permissions: 755
    \\
    \\This executable has CAP_NET_ADMIN capability and MUST NOT be
    \\world-readable, world-writable, or world-executable.
    \\
    \\To fix, run:
    \\  chmod 750 {s}
    \\  # or
    \\  chmod 700 {s}
    \\
    \\The mode must end in 0 (no permissions for "other").
    \\Access should be controlled via user/group ownership.
    \\
    \\Refusing to start for security reasons.
    \\
```

minimally for production, do the following:

1. create a special user that the nftables_port will run as such as `exfw`.  Feel free to be more creative with the name.
2. `chown exfw nftables_port`  # make the executable belong to the new user `exfw`
3. `chmod 700 nftables_port`   # make the executable only runnable by the user `exfw`

## Quick Start

### Block an IP Address 

```elixir
# Start NFTables
{:ok, pid} = NFTables.start_link()

# Build and execute a rule to block an IP
alias NFTables.{Builder, Expr}
import NFTables.Expr

Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> source_ip("192.168.1.100")
  |> drop()
)
|> Builder.submit(pid)

# That's it! The rule is now active in the kernel.
```

### Manage IP Blocklists with Sets

```elixir
{:ok, pid} = NFTables.start_link()
alias NFTables.Builder

# Add IPs to an existing blocklist set
malicious_ips = ["192.168.1.100", "10.0.0.99", "172.16.5.50"]

Builder.new()
|> Builder.add(element: malicious_ips, set: "blocklist", table: "filter", family: :inet)
|> Builder.submit(pid)

# Remove a false positive
Builder.new()
|> Builder.delete(element: ["192.168.1.100"], set: "blocklist", table: "filter", family: :inet)
|> Builder.submit(pid)

# List all blocked IPs
{:ok, %{set_elements: elements}} = NFTables.Query.list_set_elements(pid, "filter", "blocklist", family: :inet)
```

### Build Complex Rules (New API)

```elixir
alias NFTables.{Builder, Expr}
import NFTables.Expr

# Build a sophisticated firewall rule with the new fluent API
:ok = Builder.new(family: :inet)
  |> Builder.add(table: "filter")
  |> Builder.add(chain: "INPUT")
  |> Builder.add(rule: 
    expr()
    |> source_ip("10.0.0.0/8")
    |> protocol(:tcp)
    |> dport(22)
    |> ct_state([:new])
    |> limit(10, :minute, burst: 5)
    |> log("SSH_ACCESS: ", level: "info")
    |> counter()
    |> accept()
  )
  |> Builder.submit(pid)

# Or build multiple rules in a batch
:ok = Builder.new(family: :inet)
  |> Builder.add(table: "filter")
  |> Builder.add(chain: "INPUT")
  |> Builder.add(table: "filter")
  |> Builder.add(chain: "INPUT")
  |> Builder.add(rule: 
    expr() |> source_ip("10.0.0.0/8") |> drop()
  )
  |> Builder.add(rule: 
    expr() |> ct_state([:established, :related]) |> accept()
  )
  |> Builder.submit(pid)
```

### Setup Basic Firewall

```elixir
{:ok, pid} = NFTables.start_link()

# One command for secure defaults
:ok = NFTables.Policy.setup_basic_firewall(pid,
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

## New Builder + Expr API

NFTables now provides a powerful, composable API for building firewall rules:

### Builder Module - Command Construction

The `Builder` module provides a pure functional interface for constructing nftables commands:

```elixir
alias NFTables.Builder

# Build commands without executing
builder = Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")

# Execute when ready
:ok = Builder.submit(builder, pid)

# Or inspect the JSON that would be sent
json = Builder.to_json(builder)
```

### Expr Module - Composable Expression Building

The `Rule` module provides a fluent API for building rule expressions:

```elixir
alias NFTables.Expr

def established_related(rule), do: ct_state([:established, :related])

def ssh(rule, source), do: source_ip(source) |> tcp() |> dport(22)

# Build rule expressions
ssh_rule = expr()
|> ssh("10.0.0.0/8")
|> extablished_related()
|> limit(10, :minute, burst: 5)    # Rate limiting
|> log("SSH: ", level: "info")     # Logging
|> counter()                       # Add counter
|> accept()                        # Verdict
# No need to call to_list() - Builder handles conversion automatically!

# Use with Builder
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: ssh_rule)          # Automatically converted to expression list
|> Builder.submit(pid)
```

### Available Expression Matchers

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
|> Builder.add(table: "filter")
|> Builder.add(map: "port_verdict", type: {:inet_service, :verdict})
|> Builder.add(element:  [
  {80, "accept"},
  {443, "accept"},
  {8080, "drop"}
])
|> Builder.submit(pid)

# Use the map in a rule
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> protocol(:tcp)
  |> dport_map("port_verdict")  # Map lookup
)
|> Builder.submit(pid)
```

#### Named Counters

Named counters can be shared across multiple rules and queried independently:

```elixir
# Create a named counter
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(counter: "http_traffic")
|> Builder.submit(pid)

# Reference it in rules
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> protocol(:tcp)
  |> dport(80)
  |> counter_ref("http_traffic")  # Reference named counter
  |> accept()
)
|> Builder.submit(pid)
```

#### Quotas

Quotas limit the total amount of traffic (in bytes) that can pass through:

```elixir
# Create a 1 GB quota
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(quota: "monthly_limit", 1_000_000_000)
|> Builder.submit(pid)

# Use in a rule - traffic stops when quota exceeded
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(chain: "OUTPUT")
|> Builder.add(rule: 
  expr()
  |> quota_ref("monthly_limit")
  |> accept()
)
|> Builder.submit(pid)
```

#### Named Limits

Named limits provide reusable rate limiting across multiple rules:

```elixir
# Create a rate limit object
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(limit: "ssh_limit", 10, :minute, burst: 5)
|> Builder.submit(pid)

# Use in multiple rules
Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> protocol(:tcp)
  |> dport(22)
  |> limit_ref("ssh_limit")  # Reference named limit
  |> accept()
)
|> Builder.submit(pid)
```

**Benefits of Named Objects:**
- **Reusability**: Define once, use in multiple rules
- **Dynamic Updates**: Update the object without modifying rules
- **Queryable**: Check counter values, quota usage independently
- **Performance**: More efficient than inline expressions for shared logic

### Query Round-Trip Support

NFTables now supports importing existing firewall configurations back into Builder commands, enabling powerful query-modify-reapply workflows:

#### Import Entire Ruleset

```elixir
# Query and import existing firewall configuration
{:ok, builder} = Builder.from_ruleset(pid, family: :inet)

# Modify and reapply
builder
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> source_ip("192.168.1.100")
  |> drop()
)
|> Builder.submit(pid)
```

#### Import Specific Elements

```elixir
# Import tables
{:ok, tables} = Query.list_tables(pid, family: :inet)
builder = Enum.reduce(tables, Builder.new(), fn table, b ->
  Builder.import_table(b, table)
end)

# Import chains
{:ok, chains} = Query.list_chains(pid, family: :inet)
builder = Enum.reduce(chains, builder, fn chain, b ->
  Builder.import_chain(b, chain)
end)

# Import rules
{:ok, rules} = Query.list_rules(pid, family: :inet)
builder = Enum.reduce(rules, builder, fn rule, b ->
  Builder.import_rule(b, rule)
end)

# Import sets
{:ok, sets} = Query.list_sets(pid, family: :inet)
builder = Enum.reduce(sets, builder, fn set, b ->
  Builder.import_set(b, set)
end)

# Execute modified configuration
Builder.submit(builder, pid)
```

#### Use Cases

**Backup and Restore:**
```elixir
# Backup existing rules
{:ok, builder} = Builder.from_ruleset(pid)
backup_json = Builder.to_json(builder)
File.write!("firewall_backup.json", backup_json)

# Restore later
backup = File.read!("firewall_backup.json")
{:ok, restored} = Jason.decode(backup)
# Apply restored configuration...
```

**Configuration Drift Detection:**
```elixir
# Import production config
{:ok, prod_builder} = Builder.from_ruleset(prod_pid)
prod_json = Builder.to_json(prod_builder)

# Compare with expected config
{:ok, expected_builder} = Builder.from_ruleset(staging_pid)
expected_json = Builder.to_json(expected_builder)

if prod_json != expected_json do
  Logger.warning("Configuration drift detected!")
end
```

**Incremental Updates:**
```elixir
# Query existing rules for a specific chain
{:ok, rules} = Query.list_rules(pid, "filter", "INPUT")

# Build update that preserves existing rules
builder = Builder.new()
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)

# Import existing rules
builder = Enum.reduce(rules, builder, &Builder.import_rule(&2, &1))

# Add new rule
builder
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> source_ip("10.0.0.0/8")
  |> accept()
)
|> Builder.submit(pid)
```

**Benefits:**
- **Query-Modify-Reapply**: Read existing config, modify, and apply changes
- **Backup/Restore**: Export configurations for disaster recovery
- **Configuration Management**: Track and manage firewall state programmatically
- **Drift Detection**: Compare actual vs expected configurations
- **Incremental Updates**: Add rules without affecting existing ones

## Migration Guide: Old API → New API

If you're upgrading from the old convenience functions, here's how to migrate to the new Builder + Expr API:

### Blocking an IP Address

**Old API:**
```elixir
Expr.block_ip(pid, "filter", "INPUT", "192.168.1.100")
```

**New API:**
```elixir
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> source_ip("192.168.1.100")
  |> drop()
)
|> Builder.submit(pid)
```

### Accepting an IP Address

**Old API:**
```elixir
Expr.accept_ip(pid, "filter", "INPUT", "10.0.0.1")
```

**New API:**
```elixir
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> source_ip("10.0.0.1")
  |> accept()
)
|> Builder.submit(pid)
```

### Rate Limiting

**Old API:**
```elixir
Expr.rate_limit(pid, "filter", "INPUT", 10, :minute, burst: 5)
```

**New API:**
```elixir
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> limit(10, :minute, burst: 5)
  |> drop()  # or accept() depending on your use case
)
|> Builder.submit(pid)
```

### Deleting Rules

**Old API:**
```elixir
Expr.delete(pid, "filter", "INPUT", :inet, handle)
```

**New API:**
```elixir
# Query for rules first
{:ok, rules} = Query.list_rules(pid, "filter", "INPUT", family: :inet)

# Find the rule you want to delete and use Builder
rule = Enum.find(rules, fn r -> r.handle == target_handle end)

Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.delete(rule: rule.handle)
|> Builder.submit(pid)
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
Expr.list(pid, "filter", "INPUT", family: :inet)
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

### NFTables.Builder - Unified Configuration Builder

The Builder module is the primary interface for creating nftables configurations:

```elixir
alias NFTables.Builder

# Create table, chain, and set atomically
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(
  chain: "INPUT",
  table: "filter",
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)
|> Builder.add(
  set: "blocklist",
  table: "filter",
  type: :ipv4_addr
)
|> Builder.add(
  element: ["192.168.1.100", "10.0.0.50"],
  set: "blocklist",
  table: "filter"
)
|> Builder.submit(pid)

# Query operations
{:ok, tables} = NFTables.Query.list_tables(pid, family: :inet)
{:ok, chains} = NFTables.Query.list_chains(pid, family: :inet)
```

### NFTables.Expr - Rule Expression Building

The `Rule` module now provides a fluent API for building rule expressions:

```elixir
alias NFTables.{Builder, Expr}
import NFTables.Expr

# Build complex rules using the fluent API
:ok = Builder.new(family: :inet)
  |> Builder.add(table: "filter")
  |> Builder.add(chain: "INPUT")
  |> Builder.add(rule: 
    expr()
    |> source_ip("192.168.1.100")
    |> protocol(:tcp)
    |> dport(80)
    |> drop()
  )
  |> Builder.submit(pid)

# List rules using Query module
{:ok, rules} = NFTables.Query.list_rules(pid, "filter", "INPUT", family: :inet)
```

**Note**: The old `Expr.block_ip/4`, `Expr.accept_ip/4`, `Expr.rate_limit/6`, and `Expr.delete/5` functions are deprecated. See the Migration Guide above for how to use the new Builder + Expr API.

### NFTables.Expr - Pure Expression Builder

The Match module provides a streamlined, pure functional API for building rule expressions:

```elixir
import NFTables.Expr
alias NFTables.Builder

# Build rule expressions with clean, chainable API
expr = expr()
  |> source_ip("192.168.1.100")
  |> tcp()
  |> dport(22)
  |> rate_limit(5, :minute)
  |> counter()
  |> drop()

# Execute via Builder pattern
Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Builder.submit(pid: pid)

# Or use convenience aliases for more concise code
:ok = expr()
  |> source("192.168.1.100")  # alias for source_ip
  |> dport(22)                 # alias for dest_port
  |> tcp()                     # match TCP protocol
  |> limit(5, :minute)         # alias for rate_limit
  |> counter()
  |> drop()
  |> then(fn expr ->
    Builder.new()
    |> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
    |> Builder.submit(pid: pid)
  end)
```

**Key Features:**
- **Pure functional** - No side effects, expressions are data
- **Chainable API** - Build complex rules step by step
- **Convenience aliases** - `source/1`, `dest/1`, `dport/1`, `sport/1`, `tcp/1`, `udp/1`
- **Protocol helpers** - `tcp/0`, `udp/0`, `icmp/0`, `sctp/0`, `dccp/0`, `gre/0` for common protocols
- **Composable** - Build expressions in one context, execute in another
- **Advanced features** - Flowtables, meters, raw payload, TPROXY, OSF, and more

**Available Matchers:**
- **IP**: `source_ip/2`, `dest_ip/2`, `source/2`, `dest/2`
- **Ports**: `sport/2`, `dport/2`, `port/2` (supports ranges)
- **Protocol**: `protocol/2`, `tcp/1`, `udp/1`, `icmp/1`, `sctp/1`, `dccp/1`, `gre/1`
- **State**: `state/2`, `ct_state/2` - Connection tracking
- **Interface**: `iif/2`, `oif/2` - Input/output interfaces
- **Layer 2**: `source_mac/2`, `dest_mac/2`, `vlan_id/2`
- **CT**: `ct_status/2`, `ct_bytes/3`, `ct_packets/3`, `limit_connections/2`
- **Advanced**: `mark/2`, `dscp/2`, `icmp_type/2`, `tcp_flags/3`, `ttl/3`
- **Raw Payload**: `payload_raw/5`, `payload_raw_masked/6` - Deep packet inspection
- **Socket**: `socket_transparent/1` - Socket matching
- **OSF**: `osf_name/2`, `osf_version/2` - OS fingerprinting
- **SCTP/DCCP**: Use `sctp()/dccp()` for protocol, then `dport()/sport()` for ports
- **GRE**: `gre_version/2`, `gre_key/2`, `gre_flags/2` - GRE fields
- **Sets**: `in_set/3` - Match against named sets

**Available Actions:**
- **Meters**: `meter_update/5`, `meter_add/5` - Per-key rate limiting
- **Counters**: `counter/1` - Packet/byte counting
- **Logging**: `log/2` - Packet logging
- **Rate Limiting**: `limit/3`, `rate_limit/3` - Simple rate limiting
- **Marking**: `set_mark/2`, `set_connmark/2`, `save_mark/1`, `restore_mark/1`
- **Modification**: `set_dscp/2`, `set_ttl/2`, `increment_ttl/1`, `decrement_ttl/1`
- **CT**: `set_ct_label/2`, `set_ct_helper/2`, `set_ct_zone/2`

**Available Verdicts:**
- **Terminal**: `accept/1`, `drop/1`, `reject/1`, `reject/2`
- **Flow Control**: `jump/2`, `goto/2`, `return/1`, `continue/1`
- **NAT**: `snat_to/2`, `dnat_to/2`, `masquerade/1`, `redirect_to/2`
- **Advanced**: `tproxy/2` - Transparent proxy
- **Special**: `notrack/1`, `queue_to_userspace/2`, `synproxy/1`, `flow_offload/1`

See the [Match documentation](lib/nftex/match.ex) for the full API.

### NFTables.Policy - Pre-built Policies

```elixir
alias NFTables.{Policy, Builder}

# Quick firewall setup
:ok = NFTables.Policy.setup_basic_firewall(pid,
  allow_services: [:ssh, :http, :https],
  ssh_rate_limit: 10
)

# Individual policy helpers (composable - all in one transaction)
:ok =
  Builder.new()
  |> Policy.accept_loopback()
  |> Policy.accept_established()
  |> Policy.drop_invalid()
  |> Policy.allow_ssh(rate_limit: 10)
  |> Policy.allow_http()
  |> Policy.allow_https()
  |> Builder.submit(pid: pid)
```

### NFTables.Sysctl - Network Parameter Management

NFTables provides safe, whitelist-based access to kernel network parameters via `/proc/sys/net/*`. All operations use the existing CAP_NET_ADMIN capability.

```elixir
alias NFTables.{Sysctl, Sysctl.Network}

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

See `NFTables.Sysctl` and `NFTables.Sysctl.Network` documentation for the complete parameter list.

## Advanced Usage

### NAT Gateway

```elixir
alias NFTables.{Builder, NAT}

# Setup NAT with masquerading and port forwarding
Builder.new()
|> NAT.setup_masquerade("eth0", table: "nat")
|> NAT.port_forward(8080, "10.0.0.10", 80, table: "nat")
|> NAT.source_nat("10.0.0.0/24", "203.0.113.1", table: "nat")
|> Builder.submit(pid: pid)

# Static 1:1 NAT
Builder.new()
|> NAT.static_nat("203.0.113.100", "192.168.1.100", table: "nat")
|> Builder.submit(pid: pid)
```

### Connection Tracking

```elixir
import NFTables.Expr
alias NFTables.Builder

# Track connection state
expr = expr()
  |> ct_state([:established, :related])
  |> accept()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Builder.submit(pid: pid)

# Or using Policy helpers for common patterns
:ok =
  Builder.new()
  |> NFTables.Policy.accept_established()
  |> Builder.submit(pid: pid)

# Connection limits
expr = expr()
  |> tcp()
  |> dport(80)
  |> ct_state([:new])
  |> limit_connections(100)  # Max 100 concurrent connections
  |> drop()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Builder.submit(pid: pid)

# Track connection bytes
expr = expr()
  |> ct_bytes(:gt, 1_000_000)  # Over 1MB
  |> log("LARGE_TRANSFER: ")
  |> accept()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "FORWARD", family: :inet)
|> Builder.submit(pid: pid)
```

### Hardware Acceleration with Flowtables

Offload established connections to hardware for dramatic performance improvements:

```elixir
alias NFTables.Builder

# Create flowtable for hardware offloading
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(
  flowtable: "fastpath",
  hook: :ingress,
  priority: 0,
  devices: ["eth0", "eth1"]
)
|> Builder.submit(pid)

# Add rule to offload established connections
import NFTables.Expr

offload_rule = expr()
  |> state([:established, :related])
  |> flow_offload()

Builder.new()
|> Builder.add(rule: offload_rule, table: "filter", chain: "forward", family: :inet)
|> Builder.submit(pid)
```

### Per-Key Rate Limiting with Meters

Dynamic rate limiting per IP address or other keys:

```elixir
import NFTables.Expr
alias NFTables.Expr.Meter

# Per-IP SSH rate limiting
ssh_meter = expr()
  |> meter_update(
    Meter.payload(:ip, :saddr),  # Key: source IP
    "ssh_limits",                # Set name
    3,                           # 3 attempts
    :minute                      # per minute
  )
  |> tcp()
  |> dport(22)
  |> accept()

# Composite key (IP + port) for connection limits
conn_meter = expr()
  |> meter_add(
    Meter.composite_key([
      Meter.payload(:ip, :saddr),
      Meter.payload(:tcp, :dport)
    ]),
    "conn_limits",
    10,
    :second,
    burst: 5
  )
  |> accept()
```

### Deep Packet Inspection with Raw Payload

Match custom protocols using offset-based packet access:

```elixir
import NFTables.Expr

# Match DNS queries (port 53 via raw payload)
dns_block = expr()
  |> udp()
  |> payload_raw(:th, 16, 16, 53)  # Transport header, offset 16, length 16 bits, value 53
  |> log("DNS query blocked: ")
  |> drop()

# Check TCP SYN flag using masked match
syn_counter = expr()
  |> tcp()
  |> payload_raw_masked(:th, 104, 8, 0x02, 0x02)  # TCP flags offset, mask SYN bit
  |> counter()

# Match HTTP GET method
http_get = expr()
  |> tcp()
  |> dport(80)
  |> payload_raw(:ih, 0, 32, "GET ")  # Inner header, first 4 bytes
  |> log("HTTP GET: ")
  |> accept()
```

### Transparent Proxy with TPROXY

Intercept traffic without changing destination addresses:

```elixir
import NFTables.Expr
alias NFTables.Builder

# Setup transparent proxy for HTTP traffic
Builder.new(family: :ip)
|> Builder.add(table: "tproxy")
|> Builder.add(
  chain: "prerouting",
  type: :filter,
  hook: :prerouting,
  priority: -150,
  policy: :accept
)
|> Builder.submit(pid)

# Mark existing transparent sockets
mark_existing = expr()
  |> socket_transparent()
  |> set_mark(1)
  |> accept()

# TPROXY new HTTP connections
tproxy_http = expr()
  |> tcp()
  |> dport(80)
  |> mark(0)
  |> tproxy(to: 8080)

Builder.new()
|> Builder.add(rule: mark_existing, table: "tproxy", chain: "prerouting", family: :ip)
|> Builder.add(rule: tproxy_http, table: "tproxy", chain: "prerouting", family: :ip)
|> Builder.submit(pid)
```

### Specialized Protocols

Support for SCTP, DCCP, and GRE protocols:

```elixir
import NFTables.Expr

# SCTP (WebRTC data channels) - use generic dport/sport
sctp_rule = expr()
  |> sctp()
  |> dport(9899)
  |> accept()

# DCCP (streaming media) - use generic dport/sport
dccp_rule = expr()
  |> dccp()
  |> sport(5000)
  |> dport(6000)
  |> log("DCCP traffic: ")
  |> accept()

# GRE (VPN tunnels)
gre_rule = expr()
  |> gre()
  |> gre_version(0)
  |> gre_key(12345)
  |> source_ip("10.0.0.1")
  |> accept()

# Port ranges supported for SCTP/DCCP
sctp_range = expr()
  |> sctp()
  |> dport(9000..9999)
  |> counter()
```

### OS Fingerprinting

Passive operating system detection for security policies:

```elixir
import NFTables.Expr

# Allow SSH only from Linux systems
linux_ssh = expr()
  |> tcp()
  |> dport(22)
  |> osf_name("Linux")
  |> limit(10, :minute)
  |> accept()

# Rate limit Windows connections
windows_limit = expr()
  |> osf_name("Windows", ttl: :strict)
  |> limit(10, :second, burst: 5)
  |> accept()

# Block unknown OS
block_unknown = expr()
  |> osf_name("unknown")
  |> log("Unknown OS blocked: ")
  |> drop()

# OS-based marking for routing
mark_by_os = [
  expr() |> osf_name("Linux") |> set_mark(1),
  expr() |> osf_name("Windows") |> set_mark(2),
  expr() |> osf_name("MacOS") |> set_mark(3)
]
```

**Note:** OSF requires the pf.os database to be loaded:
```bash
nfnl_osf -f /usr/share/pf.os
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

{:ok, response} = NFTables.Port.call(pid, json_cmd)
result = Jason.decode!(response)
```

Or use nft command syntax:

```elixir
nft_command = "add table inet custom"
{:ok, response} = NFTables.Port.call(pid, nft_command)
```

Both are processed by `libnftables.nft_run_cmd_from_buffer()`.

## Distributed Firewall Support

NFTables supports distributed firewall architectures where a central command & control node generates firewall rules and sends them to multiple firewall nodes for execution. This is achieved through separation of command building and execution.

### Architecture

```
┌──────────────────────────────┐
│  C&C Node                    │
│  (NFTables Library)             │
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

Builder allows you to construct nftables configurations without executing them immediately:

```elixir
alias NFTables.{Builder, Match}
import Match

# Build configuration without executing
builder = Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(
  chain: "INPUT",
  table: "filter",
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)
|> Builder.add(
  rule: expr() |> source_ip("192.168.1.100") |> drop(),
  table: "filter",
  chain: "INPUT"
)

# Convert to JSON for inspection or remote execution
json_cmd = Builder.to_json(builder)

# Execute when ready
Builder.submit(builder, pid)
```

### Atomic Multi-Command Operations

Builder natively supports atomic batch operations - multiple commands are executed in a single transaction:

```elixir
alias NFTables.Builder

# Build multiple operations atomically
builder = Builder.new()
|> Builder.add(table: "filter", family: :inet)
|> Builder.add(
  table: "filter",
  chain: "INPUT",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)
|> Builder.add(set: "blocklist", table: "filter", type: :ipv4_addr)
|> Builder.add(element: ["1.2.3.4", "5.6.7.8"], set: "blocklist", table: "filter")

# Execute locally (all operations succeed or all fail - atomic)
Builder.submit(builder, pid)

# Or convert to JSON for remote execution
json = Builder.to_json(builder)
MyTransport.send_to_node("firewall-1", json)
```

### Execution Abstraction

The Builder pattern supports flexible execution via requestors:

```elixir
# Builder uses NFTables.Local requestor by default
builder = Builder.new()
|> Builder.add(table: "filter", family: :inet)
|> Builder.submit(pid: pid)  # Executes locally via NFTables.Local

# Or convert to JSON for inspection/remote execution
json = Builder.to_json(builder)
```

### Match for Remote Execution

The Match API generates pure expressions that can be combined with Builder for remote execution:

```elixir
import NFTables.Expr
alias NFTables.Builder

# Build complex rule as Builder command (not yet executed)
builder = Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(chain: "INPUT")
|> Builder.add(rule: 
  expr()
  |> source_ip("192.168.1.100")
  |> tcp()
  |> dport(22)
  |> rate_limit(10, :minute)
  |> log("SSH_ATTACK: ")
  |> drop()
)

# Convert to JSON command for remote execution
json_cmd = Builder.to_json(builder)

# Send to remote nodes
MyTransport.send_to_node("firewall-1", json_cmd)
MyTransport.send_to_node("firewall-2", json_cmd)
MyTransport.send_to_node("firewall-3", json_cmd)

# On remote nodes, execute received command
NFTables.NFTables.Local.submit(Jason.decode!(json_cmd), pid: pid)
```

### Builder Operations Reference

Builder provides a unified interface for all nftables operations:

```elixir
alias NFTables.{Builder, Match}
import Match

# Table operations
Builder.new() |> Builder.add(table: "filter", family: :inet)
Builder.new() |> Builder.delete(table: "filter", family: :inet)

# Chain operations
Builder.new()
|> Builder.add(
  chain: "INPUT",
  table: "filter",
  family: :inet,
  type: :filter,
  hook: :input,
  priority: 0,
  policy: :drop
)
|> Builder.delete(chain: "INPUT", table: "filter", family: :inet)

# Set operations
Builder.new()
|> Builder.add(set: "blocklist", table: "filter", family: :inet, type: :ipv4_addr)
|> Builder.add(element: ["192.168.1.100", "10.0.0.50"], set: "blocklist", table: "filter")
|> Builder.delete(element: ["192.168.1.100"], set: "blocklist", table: "filter")
|> Builder.delete(set: "blocklist", table: "filter", family: :inet)

# Rule operations with Match expressions
block_ip_expr = expr() |> source_ip("192.168.1.100") |> drop()
accept_ip_expr = expr() |> source_ip("10.0.0.1") |> accept()
rate_limit_expr = expr() |> tcp() |> dport(22) |> limit(10, :second) |> accept()

Builder.new()
|> Builder.add(rule: block_ip_expr, table: "filter", chain: "INPUT", family: :inet)
|> Builder.submit(pid)
```

### Complete Distributed Firewall Example

```elixir
defmodule MyApp.DistributedFirewall do
  alias NFTables.{Builder, Match}
  import Match

  # On C&C node - build firewall configuration
  def build_firewall_config() do
    # Build expressions
    loopback_expr = expr() |> source_ip("127.0.0.1") |> accept()
    ssh_rate_limit_expr = expr()
      |> tcp() |> dport(22) |> state([:new])
      |> limit(10, :minute) |> accept()

    # Build complete configuration
    Builder.new(family: :inet)
    # Create table
    |> Builder.add(table: "filter")
    # Create INPUT chain
    |> Builder.add(
      chain: "INPUT",
      table: "filter",
      type: :filter,
      hook: :input,
      priority: 0,
      policy: :drop
    )
    # Create blocklist set
    |> Builder.add(
      set: "blocklist",
      table: "filter",
      type: :ipv4_addr
    )
    # Add malicious IPs to blocklist
    |> Builder.add(
      element: ["1.2.3.4", "5.6.7.8"],
      set: "blocklist",
      table: "filter"
    )
    # Allow loopback
    |> Builder.add(rule: loopback_expr, table: "filter", chain: "INPUT")
    # Rate limit SSH
    |> Builder.add(rule: ssh_rate_limit_expr, table: "filter", chain: "INPUT")
  end

  # On C&C node - deploy to multiple firewalls
  def deploy_to_firewalls(firewall_nodes) do
    config_builder = build_firewall_config()
    json_cmd = Builder.to_json(config_builder)

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
    {:ok, pid} = NFTables.start_link()
    NFTables.Local.submit(json_cmd, pid: pid)
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

NFTables follows security best practices:

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
