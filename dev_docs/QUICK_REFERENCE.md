# NFTables Quick Reference

## New Match API Overview

The Match API is now a **pure functional expression builder**:

- ✅ **No side effects** - Build expressions as pure data
- ✅ **Dual-arity functions** - Both `tcp()` and `tcp(builder)` work
- ✅ **Chainable** - Use pipe operator naturally
- ✅ **Composable** - Build expressions, then execute separately
- ✅ **Testable** - Test expression building without execution

## How Match Works

The Match uses a **pure functional pattern** to build JSON expressions:

1. **Initialize** - Create empty expression builder
2. **Accumulate** - Each function adds JSON expression to list
3. **Execute** - Send via Builder Pattern (automatically extracts expression list)

### Visual Example

```elixir
import NFTables.Match
alias NFTables.{Builder, Local, Requestor}

# Step 1: Initialize
builder = rule()
# %Match{expr_list: [], family: :inet}

# Step 2: Accumulate expressions
builder
|> tcp()
# %Match{expr_list: [%{match: {protocol: "tcp"}}]}

|> dport(22)
# %Match{expr_list: [
#   %{match: {protocol: "tcp"}},
#   %{match: {left: {payload: {protocol: "tcp", field: "dport"}}, right: 22}}
# ]}

|> accept()
# %Match{expr_list: [
#   %{match: {protocol: "tcp"}},
#   %{match: {left: {payload: {protocol: "tcp", field: "dport"}}, right: 22}},
#   %{accept: nil}
# ]}

# Step 3: Execute - Builder automatically extracts expression list
|> then(fn rule ->
  Builder.new()
  |> Builder.add(rule: rule, table: "filter", chain: "INPUT", family: :inet)
  |> Local.submit(pid)
end)
```

### Internal Flow

```
rule()
    ↓
Pure expression building (no side effects)
    ↓
Builder.add(rule: ) - Automatically extracts expression list and adds to configuration
    ↓
Local.submit() - Send to kernel
    ↓
JSON encoding
    ↓
NFTables.Port
    ↓
libnftables
    ↓
Kernel
```

## Complex Rule Examples

### Example 1: SSH Protection

**What it does:**
- Match TCP port 22 (SSH)
- Only NEW connections
- Rate limit to 5/minute with burst
- Log violations
- Drop excessive attempts

**New API:**
```elixir
import NFTables.Match
alias NFTables.{Builder, Local, Requestor}

expr = rule()
  |> tcp()
  |> dport(22)
  |> ct_state([:new])
  |> rate_limit(5, :minute, burst: 10)
  |> log("SSH_RATELIMIT: ", level: :warn)
  |> drop()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Local.submit(pid)
```

**Convenience aliases:**
```elixir
# Using shorter function names
expr = rule()
  |> tcp()
  |> dport(22)           # alias for dest_port
  |> state([:new])       # alias for ct_state
  |> limit(5, :minute, burst: 10)  # alias for rate_limit
  |> log("SSH: ")
  |> drop()
```

### Example 2: Port Forwarding (DNAT)

**What it does:**
- Match external port 8080
- Only NEW connections
- Forward to internal server 10.0.0.10:80

**New API:**
```elixir
expr = rule()
  |> tcp()
  |> dport(8080)
  |> ct_state([:new])
  |> dnat_to("10.0.0.10", port: 80)

Builder.new()
|> Builder.add(rule: expr, table: "nat", chain: "prerouting", family: :inet)
|> Local.submit(pid)
```

### Example 3: IP Blocklist

**What it does:**
- Check if source IP in blocklist set
- Count matches
- Log blocked IPs
- Drop packet

**New API:**
```elixir
expr = rule()
  |> set("blocklist", :saddr)
  |> counter()
  |> log("BLOCKED_IP: ", level: :info)
  |> drop()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Local.submit(pid)
```

### Example 4: SYN Proxy (DDoS Protection)

**What it does:**
- Match HTTPS port (443)
- Only SYN packets
- NEW connections
- Enable SYN proxy
- Accept legitimate traffic

**New API:**
```elixir
expr = rule()
  |> tcp()
  |> dport(443)
  |> tcp_flags([:syn], [:syn, :ack, :rst, :fin])
  |> ct_state([:new])
  |> counter()
  |> synproxy(mss: 1460, wscale: 7, timestamp: true, sack_perm: true)
  |> accept()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Local.submit(pid)
```

## Key Concepts

### Dual-Arity API

All Match functions support both starting new rules and continuing existing ones:

```elixir
# Arity-1: Start new rule
tcp() |> dport(22) |> accept()

# Arity-2: Continue existing rule
builder = rule()
builder = tcp(builder)
builder = dport(builder, 22)
builder = accept(builder)

# Both work! Use whichever is clearer.
```

## Advanced Features Quick Reference

### Flowtables (Hardware Acceleration)

```elixir
# Create flowtable
Builder.new(family: :inet)
|> Builder.add(table: "filter")
|> Builder.add(
  flowtable: "fastpath",
  hook: :ingress,
  priority: 0,
  devices: ["eth0", "eth1"]
)
|> Builder.submit(pid: pid)

# Offload established connections
rule()
|> state([:established, :related])
|> flow_offload()
```

### Meters (Per-Key Rate Limiting)

```elixir
alias NFTables.Match.Meter

# Per-IP rate limiting
rule()
|> meter_update(
  Meter.payload(:ip, :saddr),
  "limits",
  10,
  :second
)
|> accept()

# Composite key (IP + port)
rule()
|> meter_add(
  Meter.composite_key([
    Meter.payload(:ip, :saddr),
    Meter.payload(:tcp, :dport)
  ]),
  "conn_limits",
  100,
  :second,
  burst: 200
)
```

### Raw Payload (Deep Packet Inspection)

```elixir
# Match DNS port via raw payload
rule()
|> udp()
|> payload_raw(:th, 16, 16, 53)  # Transport header, offset 16, 16 bits, value 53
|> drop()

# TCP SYN flag check with mask
rule()
|> tcp()
|> payload_raw_masked(:th, 104, 8, 0x02, 0x02)
|> counter()

# HTTP method detection
rule()
|> tcp()
|> dport(80)
|> payload_raw(:ih, 0, 32, "GET ")  # First 4 bytes
|> log("HTTP GET: ")
```

**Payload Bases:**
- `:ll` - Link layer (Ethernet)
- `:nh` - Network header (IP)
- `:th` - Transport header (TCP/UDP)
- `:ih` - Inner header (tunneled packets)

### Transparent Proxy (TPROXY)

```elixir
# Mark existing transparent sockets
rule()
|> socket_transparent()
|> set_mark(1)
|> accept()

# Redirect to local proxy
rule()
|> tcp()
|> dport(80)
|> tproxy(to: 8080)

# With specific address
rule()
|> tcp()
|> dport(443)
|> tproxy(to: 8443, addr: "127.0.0.1")
```

### Specialized Protocols

```elixir
# SCTP (WebRTC, telephony) - use generic dport/sport
rule()
|> sctp()
|> dport(9899)
|> accept()

# DCCP (streaming media) - use generic dport/sport
rule()
|> dccp()
|> sport(5000)
|> dport(6000)
|> counter()

# GRE (VPN tunnels)
rule()
|> gre()
|> gre_version(0)
|> gre_key(12345)
|> accept()

# Port ranges supported for SCTP/DCCP
rule()
|> sctp()
|> dport(9000..9999)
|> accept()
```

### OS Fingerprinting (OSF)

```elixir
# Match Linux systems
rule()
|> osf_name("Linux")
|> log("Linux detected: ")
|> accept()

# Match with strict TTL
rule()
|> osf_name("Windows", ttl: :strict)
|> set_mark(2)

# Match OS version
rule()
|> osf_name("Linux")
|> osf_version("3.x")
|> counter()

# Security policy
rule()
|> tcp()
|> dport(22)
|> osf_name("Linux")
|> accept()
```

**TTL Modes:** `:loose` (default), `:skip`, `:strict`
**Common OS:** "Linux", "Windows", "MacOS", "FreeBSD", "OpenBSD", "unknown"

**Requirements:**
```bash
nfnl_osf -f /usr/share/pf.os
```

### Actions vs Verdicts

**Actions** (non-terminal - rule continues):
- `counter()` - Count packets
- `log(prefix, opts)` - Log to syslog
- `rate_limit(rate, per, opts)` / `limit(...)` - Rate limiting
- `meter_update(key, set, rate, per)` - Per-key rate limiting
- `meter_add(key, set, rate, per)` - Per-key limits (add only)
- `set_mark(mark)` - Mark packets
- `set_connmark(mark)` - Mark connections
- `set_ct_label(label)` - Set CT label
- `set_dscp(dscp)` - Set DSCP value
- `continue()` - Explicit continue

**Verdicts** (terminal - rule stops):
- `accept()` - Accept packet
- `drop()` - Drop silently
- `reject(type)` - Drop with ICMP error
- `jump(chain)` - Jump to chain
- `goto(chain)` - Goto chain
- `return_from_chain()` / `return()` - Return from jump
- `tproxy(opts)` - Transparent proxy redirect
- `snat_to(ip)` / `dnat_to(ip)` - NAT
- `masquerade()` - Masquerade NAT
- `redirect_to(port)` - Port redirection
- `notrack()` - Disable connection tracking
- `flow_offload()` - Hardware offload
- `synproxy()` - SYN proxy protection
- `queue_to_userspace(num)` - Send to userspace

### Convenience Aliases

Shorter function names for common operations:

| Full Name | Alias | Example |
|-----------|-------|---------|
| `source_ip/2` | `source/2` | `source("192.168.1.1")` |
| `dest_ip/2` | `dest/2` | `dest("10.0.0.1")` |
| `source_port/2` | `sport/2` | `sport(1024)` |
| `dest_port/2` | `dport/2` | `dport(80)` |
| `dest_port/2` | `port/2` | `port(22)` |
| `ct_state/2` | `state/2` | `state([:established])` |
| `rate_limit/3` | `limit/3` | `limit(10, :minute)` |

### Protocol Helpers

Quick protocol matching:

```elixir
tcp()    # Match TCP protocol
udp()    # Match UDP protocol
icmp()   # Match ICMP protocol
sctp()   # Match SCTP protocol (WebRTC, telephony)
dccp()   # Match DCCP protocol (streaming)
gre()    # Match GRE protocol (VPN tunnels)
```

### Match Modules

Functionality is organized into sub-modules:

- **IP** - IP addresses (source/dest)
- **Port** - TCP/UDP ports
- **TCP** - Protocol-specific (flags, TTL)
- **Layer2** - MAC, interfaces, VLAN
- **CT** - Connection tracking
- **Advanced** - ICMP, marks, sets, raw payload, socket, OSF
- **Protocols** - SCTP, DCCP, GRE (specialized protocols)
- **Meter** - Per-key rate limiting with dynamic sets
- **Actions** - Counter, log, rate limit, marks
- **NAT** - SNAT, DNAT, masquerade
- **Verdicts** - accept, drop, reject, jump, TPROXY, flow offload

## Common Patterns

### Accept Established Connections
```elixir
expr = rule()
  |> state([:established, :related])
  |> accept()

Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Local.submit(pid)
```

### Rate Limit Service
```elixir
expr = rule()
  |> tcp()
  |> dport(80)
  |> limit(100, :second, burst: 200)
  |> accept()
```

### Log and Drop
```elixir
expr = rule()
  |> source("192.168.1.100")
  |> log("BLOCKED: ", level: :warn)
  |> drop()
```

### NAT Gateway
```elixir
expr = rule()
  |> oif("eth0")
  |> masquerade()

Builder.new()
|> Builder.add(rule: expr, table: "nat", chain: "postrouting", family: :inet)
|> Local.submit(pid)
```

### Connection Limit
```elixir
expr = rule()
  |> tcp()
  |> dport(80)
  |> ct_state([:new])
  |> limit_connections(100)
  |> drop()
```

## High-Level Policy Helpers

Use Policy module for common firewall patterns:

```elixir
alias NFTables.Policy

# These use the new Match API internally
:ok = Policy.accept_loopback(pid)
:ok = Policy.accept_established(pid)
:ok = Policy.drop_invalid(pid)
:ok = Policy.allow_ssh(pid, rate_limit: 10)
:ok = Policy.allow_http(pid)
:ok = Policy.allow_https(pid)
```

## Architecture Summary

```
import NFTables.Match
alias NFTables.{Builder, Local, Requestor}
    ↓
rule() - Initialize pure builder
    ↓
|> tcp() |> dport(22) |> accept() - Build expressions
    ↓
Builder.add(rule: rule_struct, ...) - Automatically extract and add to configuration
    ↓
Local.submit(pid) - Send to kernel
    ↓
JSON encoding
    ↓
NFTables.Port
    ↓
libnftables
    ↓
Kernel
```

**Benefits:**
- ✅ Pure functional - No side effects
- ✅ Composable - Build and reuse expressions
- ✅ Testable - Test without execution
- ✅ Type-safe operations
- ✅ Clear separation of concerns
- ✅ Distributed firewall friendly
