# Advanced Features

NFTables provides comprehensive support for advanced nftables capabilities that go beyond basic firewall rules. This document covers hardware acceleration, deep packet inspection, specialized protocols, and security intelligence features.

## Table of Contents

- [Hardware Acceleration & Performance](#hardware-acceleration--performance)
  - [Flowtables](#flowtables)
  - [Meters / Dynamic Sets](#meters--dynamic-sets)
- [Deep Packet Inspection](#deep-packet-inspection)
  - [Raw Payload Matching](#raw-payload-matching)
  - [Socket Matching & TPROXY](#socket-matching--tproxy)
- [Specialized Protocols](#specialized-protocols)
  - [SCTP](#sctp-stream-control-transmission-protocol)
  - [DCCP](#dccp-datagram-congestion-control-protocol)
  - [GRE](#gre-generic-routing-encapsulation)
- [Security & Intelligence](#security--intelligence)
  - [OSF (OS Fingerprinting)](#osf-os-fingerprinting)

---

## Hardware Acceleration & Performance

### Flowtables

Flowtables enable hardware-accelerated packet forwarding for established connections, dramatically improving throughput for routing and forwarding scenarios.

a#### What are Flowtables?

Flowtables offload established connection forwarding to hardware or kernel fast path, bypassing the full netfilter pipeline. This can significantly improve performance for routers, NAT gateways, and load balancers.

**Performance Impact:**
- Up to 10x throughput improvement for forwarded traffic
- Reduces CPU usage for packet processing
- Automatic hardware offload on supported NICs

#### Creating a Flowtable

```elixir
import NFTables.Expr
alias NFTables.Builder

{:ok, pid} = NFTables.Port.start_link()

# Create flowtable for fast-path forwarding
Builder.new(family: :inet)
|> NFTables.add(table: "filter")
|> NFTables.add(
  flowtable: "fastpath",
  table: "filter",
  hook: :ingress,
  priority: 0,
  devices: ["eth0", "eth1"]  # Interfaces to accelerate
)
|> NFTables.submit(pid: pid)
```

#### Using Flowtables in Rules

```elixir
# Create forward chain with flowtable offload
Builder.new(family: :inet)
|> NFTables.add(table: "filter")
|> NFTables.add(
  chain: "forward",
  table: "filter",
  type: :filter,
  hook: :forward,
  priority: 0,
  policy: :drop
)
|> NFTables.submit(pid: pid)

# Add rule to use flowtable for established connections
fastpath_rule = expr()
|> ct_state([:established, :related])
|> flow_offload("fastpath")

Builder.new()
|> NFTables.add(
  rule: fastpath_rule,
  table: "filter",
  chain: "forward",
  family: :inet
)
|> NFTables.submit(pid: pid)
```

#### Hardware Offload

Enable hardware offload on supported NICs:

```elixir
Builder.new(family: :inet)
|> NFTables.add(
  flowtable: "hwoffload",
  table: "filter",
  hook: :ingress,
  priority: 0,
  devices: ["eth0"],
  flags: [:offload]  # Enable hardware acceleration
)
|> NFTables.submit(pid: pid)
```

**Note:** Hardware offload requires:
- Linux kernel >= 5.3
- Network card with flow offload support
- Driver support for TC hardware offload

#### Use Cases

- **High-throughput routers** - Offload routing decisions to hardware
- **NAT gateways** - Accelerate connection tracking
- **Load balancers** - Reduce CPU overhead for forwarding
- **VPN gateways** - Improve tunnel throughput

---

### Meters / Dynamic Sets

Meters provide per-key rate limiting using dynamic sets. Unlike global rate limits, meters track and enforce limits independently for each key (IP address, port tuple, etc.).

#### What are Meters?

Meters combine:
- A **dynamic set** to store tracked keys
- A **key expression** (what to track: IP, port, tuple)
- A **limit statement** (rate limit per key)
- Optional **timeout** (TTL for inactive entries)

This replaces iptables' `hashlimit` with a more flexible, efficient approach.

#### Basic Per-IP Rate Limiting

```elixir
import NFTables.Expr
import NFTables.Expr.Meter
alias NFTables.Builder

{:ok, pid} = NFTables.Port.start_link()

# Step 1: Create dynamic set
Builder.new(family: :inet)
|> NFTables.add(table: "filter")
|> NFTables.add(
  set: "ssh_ratelimit",
  table: "filter",
  type: :ipv4_addr,
  flags: [:dynamic],
  timeout: 60,    # Expire entries after 60s inactivity
  size: 10000     # Max 10,000 tracked IPs
)
|> NFTables.submit(pid: pid)

# Step 2: Create rule with meter
ssh_rule = expr()
|> tcp()
|> dport(22)
|> ct_state([:new])
|> meter_update(
  Meter.payload(:ip, :saddr),  # Track by source IP
  "ssh_ratelimit",              # Set name
  3,                            # 3 connections
  :minute,                      # per minute
  burst: 5                      # Allow burst of 5
)
|> accept()

Builder.new()
|> NFTables.add(
  rule: ssh_rule,
  table: "filter",
  chain: "INPUT",
  family: :inet
)
|> NFTables.submit(pid: pid)
```

#### Composite Key Tracking

Track by multiple fields (e.g., IP + port):

```elixir
# Create set with composite key type
Builder.new(family: :inet)
|> NFTables.add(table: "filter")
|> NFTables.add(
  set: "connection_limits",
  table: "filter",
  type: {:concat, [:ipv4_addr, :inet_service]},
  flags: [:dynamic],
  timeout: 120,
  size: 50000
)
|> NFTables.submit(pid: pid)

# Use composite key in meter
limit_rule = expr()
|> tcp()
|> meter_update(
  Meter.concat([
    Meter.payload(:ip, :saddr),
    Meter.payload(:tcp, :dport)
  ]),
  "connection_limits",
  10,
  :second
)
|> accept()
```

#### Available Key Types

- **`:ipv4_addr`** - IPv4 address
- **`:ipv6_addr`** - IPv6 address
- **`:inet_service`** - Port number (16-bit)
- **`:inet_proto`** - IP protocol number
- **`{:concat, types}`** - Composite tuple of multiple fields

#### Helper Functions

```elixir
# Payload extraction
Meter.payload(:ip, :saddr)      # Source IP
Meter.payload(:ip, :daddr)      # Destination IP
Meter.payload(:tcp, :sport)     # Source port
Meter.payload(:tcp, :dport)     # Destination port

# Composite keys
Meter.concat([
  Meter.payload(:ip, :saddr),
  Meter.payload(:ip, :daddr),
  Meter.payload(:tcp, :dport)
])
```

#### Use Cases

- **SSH brute-force protection** - Limit login attempts per IP
- **HTTP flood protection** - Limit requests per source
- **Port scan detection** - Detect excessive connection attempts
- **Fair bandwidth sharing** - Limit throughput per user
- **SYN flood protection** - Limit SYN packets per source
- **API rate limiting** - Enforce per-client request limits

---

## Deep Packet Inspection

### Raw Payload Matching

Access packet headers at arbitrary byte offsets for custom protocol matching and deep packet inspection.

#### What is Raw Payload Matching?

Raw payload matching allows direct access to packet data at specific offsets, enabling:
- Matching custom or proprietary protocols
- Inspecting specific header fields
- Detecting patterns in packet payloads
- Implementing DPI (Deep Packet Inspection)

#### Header Bases

- **`:ll`** - Link layer (Ethernet)
- **`:nh`** - Network header (IP)
- **`:th`** - Transport header (TCP/UDP)
- **`:ih`** - Inner header (for tunneled packets)

#### Basic Examples

```elixir
import NFTables.Expr

# Match DNS queries (port 53) at transport header offset
dns_rule = expr()
|> udp()
|> payload_raw(:th, 16, 16, 53)  # offset=16, length=16 bits, value=53
|> accept()

# Match HTTP GET requests by payload signature
http_get_rule = expr()
|> tcp()
|> dport(80)
|> payload_raw(:ih, 0, 32, "GET ")  # First 4 bytes = "GET "
|> log("HTTP GET detected")
|> accept()

# Match specific source IP using raw payload
block_ip_rule = expr()
|> payload_raw(:nh, 96, 32, <<192, 168, 1, 1>>)  # offset 96 bits (byte 12)
|> drop()
```

#### Masked Matching

Match specific bits within a field:

```elixir
# Match TCP SYN flag (bit 1 of flags byte)
# TCP flags at offset 104 bits (13 bytes) in TCP header
syn_rule = expr()
|> tcp()
|> payload_raw_masked(
  :th,      # Transport header
  104,      # Bit offset
  8,        # Length in bits
  0x02,     # Expected value (SYN flag)
  0x02      # Mask (only check SYN bit)
)
|> counter()
|> accept()

# Match IP Don't Fragment (DF) flag
# Flags at offset 48 bits (bytes 6-7) in IP header
df_rule = expr()
|> payload_raw_masked(:nh, 48, 16, 0x4000, 0x4000)
|> counter()
|> accept()
```

#### Protocol Header Offsets

**IPv4 Header (`:nh` base):**
- Offset 0: Version + IHL (8 bits)
- Offset 64: Flags + Fragment Offset (16 bits)
- Offset 72: TTL (8 bits)
- Offset 80: Protocol (8 bits)
- Offset 96: Source IP (32 bits)
- Offset 128: Destination IP (32 bits)

**TCP Header (`:th` base):**
- Offset 0: Source Port (16 bits)
- Offset 16: Destination Port (16 bits)
- Offset 32: Sequence Number (32 bits)
- Offset 104: Flags (8 bits)

**UDP Header (`:th` base):**
- Offset 0: Source Port (16 bits)
- Offset 16: Destination Port (16 bits)
- Offset 32: Length (16 bits)

#### Use Cases

- **Custom protocol matching** - Inspect proprietary protocols
- **Application detection** - Identify applications by packet signatures
- **Security scanning** - Detect malicious payloads
- **Traffic classification** - Deep packet inspection for QoS
- **Protocol validation** - Verify header integrity

---

### Socket Matching & TPROXY

Match packets based on existing socket connections and implement transparent proxying.

#### Socket Owner Matching

Match packets by the user/group that owns the socket:

```elixir
import NFTables.Expr

# Allow traffic from specific user
user_rule = expr()
|> socket_uid(1000)
|> accept()

# Block traffic from specific group
group_rule = expr()
|> socket_gid(100)
|> drop()

# Allow traffic only from root user
root_only = expr()
|> socket_uid(0)
|> accept()
```

#### Transparent Proxy (TPROXY)

Implement transparent proxying without changing destination addresses:

```elixir
# Mark packets with existing transparent socket to prevent loops
tproxy_mark = expr()
|> socket_transparent()
|> mark(1)

# Redirect to local transparent proxy
tproxy_redirect = expr()
|> tcp()
|> dport(80)
|> mark(0)  # Not already marked
|> tproxy(port: 8080, mark: 1)
```

**TPROXY vs REDIRECT:**
- **REDIRECT** changes the destination address (requires NAT)
- **TPROXY** preserves original destination (no NAT needed)
- TPROXY is more efficient and preserves connection metadata

#### Use Cases

- **Transparent HTTP proxies** - Squid, Privoxy
- **Content filtering** - Without client configuration
- **Per-user firewall rules** - Desktop firewall policies
- **Process-based filtering** - Allow/block by application

**Note:** TPROXY requires:
- Linux kernel with TPROXY support (CONFIG_NETFILTER_XT_TARGET_TPROXY)
- Application must use `IP_TRANSPARENT` socket option
- Proper routing table configuration

---

## Specialized Protocols

### SCTP (Stream Control Transmission Protocol)

SCTP is a reliable, message-oriented transport protocol combining features of TCP and UDP.

#### What is SCTP?

**Key Features:**
- Multi-streaming (multiple independent streams in one connection)
- Multi-homing (connection survives IP address changes)
- Message boundaries (like UDP)
- Reliability (like TCP)

**Common Uses:**
- Telephony signaling (SS7/SIGTRAN)
- WebRTC data channels
- High-availability clustering (Diameter protocol)
- Mobile core networks (4G/5G)

#### SCTP Matching

```elixir
import NFTables.Expr

# Match any SCTP traffic
sctp_rule = expr()
|> sctp()
|> accept()

# SCTP with port matching (uses generic dport/sport)
signaling_rule = expr()
|> sctp()
|> dport(2905)  # SCTP M3UA port
|> source_ip("192.168.1.0/24")
|> accept()

# Rate limit SCTP connections
sctp_limit = expr()
|> sctp()
|> limit(100, :second)
|> accept()
```

**Protocol Number:** SCTP uses IP protocol 132

---

### DCCP (Datagram Congestion Control Protocol)

DCCP provides congestion control for unreliable datagrams.

#### What is DCCP?

**Key Features:**
- Unreliable delivery (like UDP)
- Congestion control (unlike UDP)
- Connection-oriented (handshake)
- Multiple congestion control algorithms

**Common Uses:**
- Streaming media (video, audio)
- Online gaming
- Real-time applications tolerating packet loss
- VoIP (alternative to RTP/UDP)

#### DCCP Matching

```elixir
import NFTables.Expr

# Match any DCCP traffic
dccp_rule = expr()
|> dccp()
|> counter()
|> accept()

# DCCP with port matching
streaming_rule = expr()
|> dccp()
|> dport(5000..6000)  # Streaming port range
|> log("DCCP stream")
|> accept()

# Source-based DCCP filtering
trusted_dccp = expr()
|> dccp()
|> source_ip("10.0.0.0/8")
|> accept()
```

**Protocol Number:** DCCP uses IP protocol 33

---

### GRE (Generic Routing Encapsulation)

GRE is a tunneling protocol for encapsulating network layer protocols.

#### What is GRE?

**Key Features:**
- Encapsulates various protocols
- Creates virtual point-to-point links
- Commonly used for VPN tunnels
- Supports multicast traffic

**Common Uses:**
- VPN tunnels (PPTP uses GRE)
- Site-to-site connections
- IP-in-IP tunneling
- Multicast across networks

#### GRE Matching

```elixir
import NFTables.Expr

# Match any GRE traffic
gre_rule = expr()
|> gre()
|> accept()

# Match specific GRE version
gre_v0 = expr()
|> gre()
|> gre_version(0)
|> accept()

# Filter GRE by source
vpn_tunnel = expr()
|> gre()
|> source_ip("203.0.113.0/24")
|> counter()
|> accept()
```

**Protocol Number:** GRE uses IP protocol 47

#### GRE Tunnel Example

```elixir
# Allow GRE from known tunnel endpoints
tunnel_endpoints = ["203.0.113.1", "203.0.113.2"]

Enum.each(tunnel_endpoints, fn endpoint ->
  gre_rule = expr()
  |> gre()
  |> source_ip(endpoint)
  |> log("GRE tunnel from #{endpoint}")
  |> accept()

  Builder.new()
  |> NFTables.add(rule: gre_rule, table: "filter", chain: "INPUT")
  |> NFTables.submit(pid: pid)
end)
```

---

## Security & Intelligence

### OSF (OS Fingerprinting)

Passive operating system detection via TCP SYN packet analysis.

#### What is OSF?

OSF (Operating System Fingerprinting) analyzes TCP SYN packets to identify the client's operating system without active scanning. This works by examining:
- TCP window size
- TCP options and their order
- TTL values
- Window scaling
- Other TCP quirks

#### Prerequisites

1. **Load signature database:**

```bash
# Install pf (packet filter) OS signatures
sudo apt-get install p0f

# Load signatures into kernel
sudo nfnl_osf -f /usr/share/pf.os
```

2. **Kernel support:**
   - Linux kernel with `CONFIG_NETFILTER_NETLINK_OSF`
   - `nfnetlink_osf` module loaded

#### Basic Usage

```elixir
import NFTables.Expr

# Detect Windows clients
windows_rule = expr()
|> tcp()
|> osf_name("Windows")
|> log("Windows client detected")
|> accept()

# Detect Linux clients
linux_rule = expr()
|> osf_name("Linux")
|> counter()
|> accept()

# Detect unknown OS
unknown_os = expr()
|> osf_name("unknown")
|> log("Unknown OS")
|> drop()
```

#### TTL Matching Modes

```elixir
# Loose TTL matching (default) - allows TTL differences
loose_match = expr()
|> osf_name("Linux")
|> accept()

# Strict TTL matching - requires exact TTL
strict_match = expr()
|> osf_name("Windows", ttl: :strict)
|> accept()
```

#### Practical Examples

**OS-based traffic shaping:**

```elixir
# Set QoS marks based on OS
os_qos_rules = [
  expr() |> osf_name("Linux") |> set_mark(1),
  expr() |> osf_name("Windows") |> set_mark(2),
  expr() |> osf_name("MacOS") |> set_mark(3)
]

Enum.each(os_qos_rules, fn qos_rule ->
  Builder.new()
  |> NFTables.add(rule: qos_rule, table: "filter", chain: "FORWARD")
  |> NFTables.submit(pid: pid)
end)
```

**Security filtering:**

```elixir
# Block old/vulnerable OS versions
block_old_os = expr()
|> tcp()
|> dport(22)  # SSH
|> osf_name("Windows")  # Could add version detection
|> log("Blocked obsolete OS from SSH")
|> reject()

# Allow only known corporate OS images
corporate_os = expr()
|> tcp()
|> osf_name("Linux")
|> source_ip("10.0.0.0/8")
|> accept()
```

#### Use Cases

- **Security enforcement** - Block connections from obsolete/insecure OS versions
- **Network analytics** - Track OS distribution across network
- **Targeted policies** - Apply different rules per OS type
- **Compliance monitoring** - Ensure only approved OS versions connect
- **Traffic shaping** - Different QoS per OS type
- **Anomaly detection** - Alert on unexpected OS types

#### Limitations

- **Passive only** - Requires incoming TCP SYN packets
- **Signature database** - Must be kept up to date
- **Accuracy** - Can be fooled by modified TCP stacks
- **Coverage** - Not all OS versions may be in database

---

## Performance Considerations

### Flowtables

- **Best for:** High packet-per-second forwarding scenarios
- **Overhead:** Minimal after flow offload
- **Memory:** Per-flow state (typically 256 bytes per flow)

### Meters

- **Best for:** Per-key rate limiting with many keys
- **Overhead:** Hash table lookup per packet
- **Memory:** Proportional to number of tracked keys
- **Cleanup:** Automatic via timeouts

### Raw Payload

- **Best for:** Deep packet inspection when needed
- **Overhead:** Higher than standard matching
- **Tip:** Combine with protocol matching to reduce overhead

### Socket Matching

- **Best for:** Local firewall (not routers)
- **Overhead:** Socket lookup per packet
- **Limitation:** Only works for locally-generated traffic

---

## Further Reading

- [nftables wiki - Flowtables](https://wiki.nftables.org/wiki-nftables/index.php/Flowtables)
- [nftables wiki - Meters](https://wiki.nftables.org/wiki-nftables/index.php/Meters)
- [Linux kernel - nf_tables](https://www.kernel.org/doc/html/latest/networking/nf_tables.html)
- [SCTP RFC 4960](https://tools.ietf.org/html/rfc4960)
- [DCCP RFC 4340](https://tools.ietf.org/html/rfc4340)
- [GRE RFC 2784](https://tools.ietf.org/html/rfc2784)

---

## API Reference

For complete API documentation, see:
- `lib/nftables/match/meter.ex` - Meter functions
- `lib/nftables/match/advanced.ex` - OSF, socket, raw payload matching
- `lib/nftables/match/protocols.ex` - SCTP, DCCP, GRE matching
- `lib/nftables/builder.ex` - Flowtable creation
