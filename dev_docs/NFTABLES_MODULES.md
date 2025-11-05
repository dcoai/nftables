# NFTables Modules - Implementation Status and Examples

This document provides a complete overview of all nftables components, their implementation status in NFTex, and examples showing the highest-level abstraction available for each.

**Last Updated:** 2025-11-03

---

## Legend

- ✅ **High-Level API Available**: Use `NFTex.Module.operation()`
- ⚡ **Partial High-Level**: Some operations have high-level API, complex cases require Kernel API
- 🔧 **Kernel-Only**: Use `NFTex.Kernel.Module.operation()`
- ❌ **Not Implemented**: Feature not yet available in NFTex

---

## Quick Reference Table

| Component | Status | High-Level Module | Kernel Module |
|-----------|--------|-------------------|---------------|
| Tables | ⚡ Partial | `NFTex.Table` | `NFTex.Kernel.Table` |
| Chains | ⚡ Partial | `NFTex.Chain` | `NFTex.Kernel.Chain` |
| Rules | 🔧 Kernel-Only | `NFTex.Rule` | `NFTex.Kernel.Rule` |
| Expressions | 🔧 Kernel-Only | - | `NFTex.Kernel.Expression` |
| Sets | ⚡ Partial | `NFTex.Set` | `NFTex.Kernel.Set` |
| Set Elements | 🔧 Kernel-Only | - | `NFTex.Kernel.SetElement` |
| Batches | 🔧 Kernel-Only | - | `NFTex.Kernel.Batch` |
| Flowtables | ❌ Not Implemented | - | - |
| Stateful Objects | ❌ Not Implemented | - | - |

---

## Core Components

### Tables ⚡ Partial High-Level

**Purpose**: Container for chains, organized by protocol family

**Implementation Status**: Basic creation/deletion (netlink send not yet implemented)

#### High-Level API (`NFTex.Table`)

```elixir
{:ok, pid} = NFTex.start_link()

# Create table
NFTex.Table.create(pid, %{
  name: "filter",
  family: :inet,  # :inet, :ip, :ip6, :arp, :bridge, :netdev
  flags: []
})

# Delete table (not yet implemented)
NFTex.Table.delete(pid, "filter", :inet)

# List tables (not yet implemented)
{:ok, tables} = NFTex.Table.list(pid, :inet)
```

#### Low-Level API (`NFTex.Kernel.Table`)

```elixir
# Manual resource management
{:ok, table_id} = NFTex.Kernel.Table.alloc(pid)
:ok = NFTex.Kernel.Table.set_str(pid, table_id, :name, "filter")
:ok = NFTex.Kernel.Table.set_u32(pid, table_id, :family, 2)  # AF_INET

# Get attributes
{:ok, name} = NFTex.Kernel.Table.get_str(pid, table_id, :name)
{:ok, family} = NFTex.Kernel.Table.get_u32(pid, table_id, :family)

# Must free when done
:ok = NFTex.Kernel.Table.free(pid, table_id)
```

**Status Notes**:
- ✅ Resource allocation/free working
- ✅ Attribute setting/getting working
- ❌ Netlink send/receive not yet implemented
- ❌ Kernel communication pending

---

### Chains ⚡ Partial High-Level

**Purpose**: Container for rules, can be base chain (hooked) or regular chain

**Implementation Status**: Basic creation (netlink send not yet implemented)

#### High-Level API (`NFTex.Chain`)

```elixir
# Create base chain (hooked to netfilter)
NFTex.Chain.create(pid, %{
  table: "filter",
  name: "input",
  family: :inet,
  type: :filter,      # :filter, :nat, :route
  hook: :input,       # :prerouting, :input, :forward, :output, :postrouting
  priority: 0,
  policy: :accept     # :accept or :drop
})

# Create regular chain (not hooked)
NFTex.Chain.create(pid, %{
  table: "filter",
  name: "custom_rules",
  family: :inet
})

# Delete chain (not yet implemented)
NFTex.Chain.delete(pid, "filter", "input", :inet)
```

#### Low-Level API (`NFTex.Kernel.Chain`)

```elixir
{:ok, chain_id} = NFTex.Kernel.Chain.alloc(pid)
:ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :name, "input")
:ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :table, "filter")
:ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :family, 2)

# For base chains
:ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :type, "filter")
:ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :hooknum, 1)  # INPUT
:ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :prio, 0)
:ok = NFTex.Kernel.Chain.set_u8(pid, chain_id, :policy, 1)   # ACCEPT

# Get attributes
{:ok, name} = NFTex.Kernel.Chain.get_str(pid, chain_id, :name)
{:ok, hooknum} = NFTex.Kernel.Chain.get_u32(pid, chain_id, :hooknum)

:ok = NFTex.Kernel.Chain.free(pid, chain_id)
```

---

### Rules 🔧 Kernel-Only

**Purpose**: Contains expressions that match packets and take actions

**Implementation Status**: Low-level API only (high-level requires expression building)

#### Why Kernel-Only

Rules are complex because they contain expressions. Building a high-level API
requires implementing expression builders for 30+ expression types, register
allocation, and expression ordering logic.

#### Low-Level API (`NFTex.Kernel.Rule`)

```elixir
# Create rule
{:ok, rule_id} = NFTex.Kernel.Rule.alloc(pid)
:ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :table, "filter")
:ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :chain, "input")
:ok = NFTex.Kernel.Rule.set_u32(pid, rule_id, :family, 2)

# Build expressions (see Expression section)
{:ok, counter_id} = NFTex.Kernel.Expression.alloc(pid, "counter")
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, counter_id)

# Get attributes
{:ok, table} = NFTex.Kernel.Rule.get_str(pid, rule_id, :table)
{:ok, family} = NFTex.Kernel.Rule.get_u32(pid, rule_id, :family)

:ok = NFTex.Kernel.Rule.free(pid, rule_id)
```

**Future High-Level API** (planned):
```elixir
NFTex.Rule.create(pid, %{
  table: "filter",
  chain: "input",
  family: :inet,
  expressions: [
    {:match_ip_source, "192.168.1.100"},
    {:counter},
    {:verdict, :drop}
  ]
})
```

---

## Expression Types

Expressions are the building blocks of rules. nftables supports 30+ types.

### General Expression API 🔧 Kernel-Only

All expressions use the same allocation interface:

```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "expression_type")
:ok = NFTex.Kernel.Expression.set_u8/u16/u32/u64/str/data(pid, expr_id, :attr, value)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
# Expression now owned by rule - don't free it
```

---

### Counter Expression 🔧 Kernel-Only

**Purpose**: Count packets and bytes matching a rule

**Attributes**: None (counter has no configuration)

**Example**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "counter")
# No attributes to set
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Payload Expression 🔧 Kernel-Only

**Purpose**: Match or extract packet header data

**Attributes**:
- `:base` - Base type (0=link, 1=network, 2=transport)
- `:offset` - Byte offset in header
- `:len` - Length in bytes
- `:dreg` - Destination register (1-16)

**Example - Match IPv4 source address**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "payload")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :base, 1)      # NETWORK
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :offset, 12)   # IP src offset
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :len, 4)       # 4 bytes
:ok = NFTex.Kernel.Expression.set_u8(pid, expr_id, :dreg, 1)       # Store in reg1
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

**Example - Match TCP destination port**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "payload")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :base, 2)      # TRANSPORT
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :offset, 2)    # TCP dport offset
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :len, 2)       # 2 bytes
:ok = NFTex.Kernel.Expression.set_u8(pid, expr_id, :dreg, 2)       # Store in reg2
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Comparison Expression 🔧 Kernel-Only

**Purpose**: Compare register value with data

**Attributes**:
- `:op` - Operation (0=eq, 1=neq, 2=lt, 3=lte, 4=gt, 5=gte)
- `:sreg` - Source register (1-16)
- `:data` - Binary data to compare against

**Example - Compare IP address in register 1**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "cmp")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :op, 0)        # EQ
:ok = NFTex.Kernel.Expression.set_u8(pid, expr_id, :sreg, 1)       # Check reg1
:ok = NFTex.Kernel.Expression.set_data(pid, expr_id, :data, <<192, 168, 1, 100>>)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Immediate Expression (Verdict) 🔧 Kernel-Only

**Purpose**: Set verdicts or load immediate values

**Attributes**:
- `:verdict` - Verdict code (0=drop, 1=accept, etc.)
- `:dreg` - Destination register (for immediate values)
- `:data` - Immediate data value

**Example - Drop verdict**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "immediate")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :verdict, 0)   # DROP
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

**Example - Accept verdict**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "immediate")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :verdict, 1)   # ACCEPT
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### NAT Expression 🔧 Kernel-Only

**Purpose**: Network address translation

**Attributes**:
- `:type` - NAT type (0=snat, 1=dnat)
- `:family` - Protocol family
- `:reg_addr_min` - Register with min address
- `:reg_addr_max` - Register with max address
- `:reg_proto_min` - Register with min port (optional)
- `:reg_proto_max` - Register with max port (optional)
- `:flags` - NAT flags

**Example - SNAT (masquerading)**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "nat")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :type, 0)      # SNAT
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :family, 2)    # IPv4
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :reg_addr_min, 1)
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :reg_addr_max, 1)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Limit Expression 🔧 Kernel-Only

**Purpose**: Rate limiting

**Attributes**:
- `:rate` - Rate value
- `:unit` - Time unit (0=second, 1=minute, 2=hour, 3=day)
- `:burst` - Burst size
- `:type` - Limit type (0=packets, 1=bytes)
- `:flags` - Limit flags

**Example - 10 packets per second**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "limit")
:ok = NFTex.Kernel.Expression.set_u64(pid, expr_id, :rate, 10)
:ok = NFTex.Kernel.Expression.set_u64(pid, expr_id, :unit, 0)      # per second
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :burst, 5)
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :type, 0)      # packets
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :flags, 0)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Log Expression 🔧 Kernel-Only

**Purpose**: Log packets to kernel log

**Attributes**:
- `:prefix` - Log prefix string
- `:level` - Log level (0-7, syslog levels)
- `:group` - Netfilter log group
- `:snaplen` - Snapshot length
- `:qthreshold` - Queue threshold

**Example - Log with prefix**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "log")
:ok = NFTex.Kernel.Expression.set_str(pid, expr_id, :prefix, "DROPPED: ")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :level, 4)     # WARNING
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :group, 0)
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :snaplen, 0)
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :qthreshold, 1)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Connection Tracking Expression 🔧 Kernel-Only

**Purpose**: Match connection tracking state

**Attributes**:
- `:key` - CT key type (0=state, 1=direction, 2=status, etc.)
- `:dreg` - Destination register
- `:direction` - Direction (0=original, 1=reply)

**Example - Match established connections**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "ct")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :key, 0)       # STATE
:ok = NFTex.Kernel.Expression.set_u8(pid, expr_id, :dreg, 1)
:ok = NFTex.Kernel.Expression.set_u8(pid, expr_id, :direction, 0)  # ORIGINAL
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Quota Expression 🔧 Kernel-Only

**Purpose**: Bandwidth quota enforcement

**Attributes**:
- `:bytes` - Quota in bytes
- `:flags` - Quota flags (0=consumed, 1=inverted)

**Example - 1GB quota**:
```elixir
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "quota")
:ok = NFTex.Kernel.Expression.set_u64(pid, expr_id, :bytes, 1_073_741_824)
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :flags, 0)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
```

---

### Other Expression Types 🔧 Kernel-Only

The following expression types are supported but require reading
`/usr/include/libnftnl/expr.h` for attribute details:

- **meta** - Packet metadata (interface, mark, etc.)
- **lookup** - Set/map lookups
- **dynset** - Dynamic set operations (meters)
- **rt** - Routing information
- **fib** - Forwarding information base
- **hash** - Hashing for load balancing
- **numgen** - Number generation (random/incremental)
- **range** - Range comparisons
- **reject** - Reject packets with ICMP
- **bitwise** - Bitwise operations
- **byteorder** - Byte order conversion
- **queue** - Queue to userspace
- **socket** - Socket matching
- **osf** - OS fingerprinting
- **xfrm** - IPsec/XFRM matching
- **tunnel** - Tunnel matching
- **inner** - Inner packet matching
- **tproxy** - Transparent proxy
- **synproxy** - SYN proxy
- **dup** - Packet duplication
- **fwd** - Packet forwarding
- **masq** - Masquerading
- **redir** - Port redirection
- **exthdr** - IPv6 extension headers
- **last** - Last packet timestamp
- **connlimit** - Connection limiting
- **match** - iptables match (legacy)
- **target** - iptables target (legacy)

---

## Sets and Elements

### Sets ⚡ Partial High-Level

**Purpose**: Efficient matching against multiple values

**Implementation Status**: Simple sets work, advanced features require Kernel API

#### High-Level API (`NFTex.Set`)

```elixir
# Simple IP address set
NFTex.Set.create(pid, %{
  name: "banned_ips",
  table: "filter",
  family: :inet,
  key_type: :ipv4_addr,  # :ipv4_addr, :ipv6_addr, :ether_addr, :inet_protocol, :inet_service
  elements: [
    <<192, 168, 1, 100>>,
    <<192, 168, 1, 101>>,
    <<192, 168, 1, 102>>
  ]
})

# Not yet implemented:
NFTex.Set.delete(pid, "filter", "banned_ips", :inet)
NFTex.Set.add_elements(pid, "filter", "banned_ips", :inet, [<<10, 0, 0, 1>>])
NFTex.Set.delete_elements(pid, "filter", "banned_ips", :inet, [<<192, 168, 1, 100>>])
```

#### Low-Level API (`NFTex.Kernel.Set`)

```elixir
# Create set
{:ok, set_id} = NFTex.Kernel.Set.alloc(pid)
:ok = NFTex.Kernel.Set.set_str(pid, set_id, :name, "banned_ips")
:ok = NFTex.Kernel.Set.set_str(pid, set_id, :table, "filter")
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :family, 2)      # IPv4
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_type, 7)    # IPv4 addr
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_len, 4)

# For map sets (key -> value)
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :data_type, 1)   # Counter
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :data_len, 16)

# Add elements - see SetElement section
:ok = NFTex.Kernel.Set.free(pid, set_id)
```

---

### Set Elements 🔧 Kernel-Only

**Purpose**: Individual entries in a set

**Important**: Elements are owned by the set after adding. Don't free them!

```elixir
# Create element
{:ok, elem_id} = NFTex.Kernel.SetElement.alloc(pid)
:ok = NFTex.Kernel.SetElement.set_data(pid, elem_id, :key, <<192, 168, 1, 100>>)

# For map sets, also set data
:ok = NFTex.Kernel.SetElement.set_data(pid, elem_id, :data, <<0, 0, 0, 1>>)

# Add to set (transfers ownership!)
:ok = NFTex.Kernel.SetElement.add(pid, set_id, elem_id)
# Don't free elem_id now - it's owned by set_id
```

---

## Batch Operations

### Batches 🔧 Kernel-Only

**Purpose**: Build netlink messages for atomic operations

**Implementation Status**: Allocation works, netlink operations not yet complete

```elixir
# Allocate batch with default parameters
{:ok, batch_id} = NFTex.Kernel.Batch.alloc(pid)

# Or with custom parameters
{:ok, batch_id} = NFTex.Kernel.Batch.alloc(pid, 8192, 10)

# Build messages and add to batch (TODO: requires netlink bindings)
# ...

:ok = NFTex.Kernel.Batch.free(pid, batch_id)
```

---

## Advanced Features (Not Yet Implemented)

### Flowtables ❌ Not Implemented

**Purpose**: Hardware/software flow offloading

**Required C Bindings**: `nftnl_flowtable_*`

**Expected API** (when implemented):
```elixir
{:ok, flowtable_id} = NFTex.Kernel.Flowtable.alloc(pid)
:ok = NFTex.Kernel.Flowtable.set_str(pid, flowtable_id, :name, "f")
:ok = NFTex.Kernel.Flowtable.set_u32(pid, flowtable_id, :hooknum, 0)
:ok = NFTex.Kernel.Flowtable.set_u32(pid, flowtable_id, :priority, 0)
:ok = NFTex.Kernel.Flowtable.add_device(pid, flowtable_id, "eth0")
```

---

### Stateful Objects ❌ Not Implemented

**Purpose**: Named counters, quotas, limits shared across rules

**Required C Bindings**: `nftnl_obj_*`

**Expected API** (when implemented):
```elixir
# Named counter
{:ok, obj_id} = NFTex.Kernel.Object.alloc(pid, :counter)
:ok = NFTex.Kernel.Object.set_str(pid, obj_id, :name, "http_counter")
:ok = NFTex.Kernel.Object.set_str(pid, obj_id, :table, "filter")

# Reference in rule via objref expression
{:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "objref")
:ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :type, 1)      # counter
:ok = NFTex.Kernel.Expression.set_str(pid, expr_id, :name, "http_counter")
```

---

## Complete Example: Block an IP Address

This example shows how to build a complete firewall rule to block an IP address
using the current Kernel API.

```elixir
{:ok, pid} = NFTex.start_link()

# Create table
{:ok, table_id} = NFTex.Kernel.Table.alloc(pid)
:ok = NFTex.Kernel.Table.set_str(pid, table_id, :name, "filter")
:ok = NFTex.Kernel.Table.set_u32(pid, table_id, :family, 2)
# TODO: Send to kernel
:ok = NFTex.Kernel.Table.free(pid, table_id)

# Create chain
{:ok, chain_id} = NFTex.Kernel.Chain.alloc(pid)
:ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :name, "input")
:ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :table, "filter")
:ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :family, 2)
:ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :type, "filter")
:ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :hooknum, 1)  # INPUT
:ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :prio, 0)
:ok = NFTex.Kernel.Chain.set_u8(pid, chain_id, :policy, 1)    # ACCEPT
# TODO: Send to kernel
:ok = NFTex.Kernel.Chain.free(pid, chain_id)

# Create rule
{:ok, rule_id} = NFTex.Kernel.Rule.alloc(pid)
:ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :table, "filter")
:ok = NFTex.Kernel.Rule.set_str(pid, rule_id, :chain, "input")
:ok = NFTex.Kernel.Rule.set_u32(pid, rule_id, :family, 2)

# Expression 1: Load IP source address into register 1
{:ok, payload_id} = NFTex.Kernel.Expression.alloc(pid, "payload")
:ok = NFTex.Kernel.Expression.set_u32(pid, payload_id, :base, 1)      # NETWORK
:ok = NFTex.Kernel.Expression.set_u32(pid, payload_id, :offset, 12)   # IP src
:ok = NFTex.Kernel.Expression.set_u32(pid, payload_id, :len, 4)
:ok = NFTex.Kernel.Expression.set_u8(pid, payload_id, :dreg, 1)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, payload_id)

# Expression 2: Compare register 1 with target IP
{:ok, cmp_id} = NFTex.Kernel.Expression.alloc(pid, "cmp")
:ok = NFTex.Kernel.Expression.set_u32(pid, cmp_id, :op, 0)            # EQ
:ok = NFTex.Kernel.Expression.set_u8(pid, cmp_id, :sreg, 1)
:ok = NFTex.Kernel.Expression.set_data(pid, cmp_id, :data, <<192, 168, 1, 100>>)
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, cmp_id)

# Expression 3: Counter (optional)
{:ok, counter_id} = NFTex.Kernel.Expression.alloc(pid, "counter")
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, counter_id)

# Expression 4: Drop verdict
{:ok, verdict_id} = NFTex.Kernel.Expression.alloc(pid, "immediate")
:ok = NFTex.Kernel.Expression.set_u32(pid, verdict_id, :verdict, 0)   # DROP
:ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, verdict_id)

# TODO: Send rule to kernel
:ok = NFTex.Kernel.Rule.free(pid, rule_id)

NFTex.stop(pid)
```

**With future high-level API, this would be**:
```elixir
{:ok, pid} = NFTex.start_link()

NFTex.Table.create(pid, %{name: "filter", family: :inet})
NFTex.Chain.create(pid, %{
  table: "filter", name: "input", family: :inet,
  type: :filter, hook: :input, priority: 0, policy: :accept
})
NFTex.Rule.create(pid, %{
  table: "filter", chain: "input", family: :inet,
  expressions: [
    {:match_ip_source, "192.168.1.100"},
    {:counter},
    {:verdict, :drop}
  ]
})

NFTex.stop(pid)
```

---

## Implementation Roadmap

### Current Status (Phase 10)
- ✅ Low-level Kernel API modules created
- ✅ High-level API modules created (partial implementation)
- ✅ Resource management working
- ❌ Netlink send/receive not yet implemented
- ❌ Expression attribute constants missing (critical bug)

### Next Steps

#### Priority 1: Fix Critical Issues
1. Add expression-specific attribute constants to libnftnl.zig
2. Fix expression attribute handling (currently uses incorrect hash-based IDs)
3. Implement netlink socket operations
4. Test against actual kernel

#### Priority 2: Complete Low-Level API
1. Add flowtable bindings
2. Add stateful object bindings
3. Add netlink query/list operations
4. Add delete operations

#### Priority 3: Enhance High-Level API
1. Implement NFTex.Table.delete/list
2. Implement NFTex.Chain.delete
3. Implement NFTex.Set operations
4. Start NFTex.Rule high-level building

#### Priority 4: Expression Helpers
1. Create NFTex.Expression.* modules for common types
2. Implement register allocation helper
3. Add validation and error messages

#### Priority 5: Helper Modules
1. NFTex.Helpers.Firewall - Common firewall patterns
2. NFTex.Helpers.NAT - NAT scenarios
3. Domain-specific DSL (future)

---

## Notes on Expression Attribute IDs

**CRITICAL ISSUE**: The current implementation uses hash-based attribute IDs (see
commands.zig lines 1060, 1102, etc). This is WRONG.

Each expression type has specific attribute constants defined in
`/usr/include/libnftnl/expr.h`, for example:

```c
// Payload expression
#define NFTNL_EXPR_PAYLOAD_DREG     0
#define NFTNL_EXPR_PAYLOAD_BASE     1
#define NFTNL_EXPR_PAYLOAD_OFFSET   2
#define NFTNL_EXPR_PAYLOAD_LEN      3

// Comparison expression
#define NFTNL_EXPR_CMP_SREG         0
#define NFTNL_EXPR_CMP_OP           1
#define NFTNL_EXPR_CMP_DATA         2
```

These constants must be added to libnftnl.zig and used instead of hash-based IDs.

---

## Getting Help

- For high-level API examples, see the examples in this document
- For low-level API details, consult `/usr/include/libnftnl/*.h`
- For nftables concepts, see https://wiki.nftables.org/
- For kernel netlink protocol, see `man nft` and kernel documentation

---

**Document Version**: 1.0
**Last Updated**: 2025-11-03
**Next Review**: After netlink implementation
