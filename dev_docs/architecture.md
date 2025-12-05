# NFTables Library Architecture

This document provides a deep dive into the architecture of the NFTables library, explaining the design decisions, component interactions, and composition patterns that make the library work.

## Table of Contents

- [High-Level Overview](#high-level-overview)
- [NFTables.Port Separation](#nftablesport-separation)
- [Core Architecture Components](#core-architecture-components)
- [Builder Architecture](#builder-architecture)
- [Match and Rule Building](#match-and-rule-building)
- [Composition Patterns](#composition-patterns)
- [Data Flow and Execution Pipeline](#data-flow-and-execution-pipeline)
- [Requestor Pattern](#requestor-pattern)
- [Design Principles](#design-principles)

---

## High-Level Overview

The NFTables library is built on a layered architecture that separates concerns and provides multiple levels of abstraction for working with Linux nftables:

```
┌─────────────────────────────────────────────────────────┐
│  High-Level API (Policy, NAT, convenience functions)    │
├─────────────────────────────────────────────────────────┤
│  Builder API (tables, chains, sets, flowtables)         │
│  Match/Rule API (rule expressions)                      │
├─────────────────────────────────────────────────────────┤
│  Core Layer (Query, Local, Requestor, Decoder, Expr)    │
├─────────────────────────────────────────────────────────┤
│  NFTables.Port (GenServer managing Zig port process)    │
├─────────────────────────────────────────────────────────┤
│  Port Executable (Zig binary with CAP_NET_ADMIN)        │
├─────────────────────────────────────────────────────────┤
│  libnftables (Official C library, JSON API)             │
├─────────────────────────────────────────────────────────┤
│  Linux Kernel (nftables netfilter subsystem)            │
└─────────────────────────────────────────────────────────┘
```

Each layer builds upon the one below it, with clear boundaries and responsibilities.

---

## NFTables.Port Separation

### Why Separate NFTables.Port?

The `nftables_port` package is maintained as a **separate repository and Hex package** from the main `nftables` library. This separation provides several critical benefits:

#### 1. **Fault Isolation**

The port process runs as a separate OS process. If the native code crashes (due to C library issues, memory corruption, etc.), it doesn't bring down the Elixir VM:

```elixir
# Port crashes are isolated - BEAM continues running
{:ok, pid} = NFTables.Port.start_link()
# If port crashes, only this GenServer crashes
# Supervisor can restart it without affecting the rest of the application
```

#### 2. **Security Boundary**

The port executable requires `CAP_NET_ADMIN` capability to communicate with the kernel firewall. By isolating this in a separate process:

- Only the port binary needs elevated privileges
- The Elixir VM runs with normal user permissions
- Attack surface is minimized to a small, auditable Zig program
- Principle of least privilege is enforced

```bash
# Only the port needs capabilities
sudo setcap cap_net_admin=ep priv/port_nftables

# Elixir app runs as regular user
mix run --no-halt
```

#### 3. **Technology Isolation**

Native dependencies (Zig compiler, libnftables) are isolated to the port package:

- Main library has zero native dependencies
- Can be developed/tested without Zig toolchain
- Updates to port implementation don't require library changes
- Different deployment scenarios (local vs. remote execution)

#### 4. **Independent Versioning**

Port and library can version independently:

```elixir
# mix.exs
def deps do
  [
    {:nftables_port, "~> 0.4.0"},  # Port protocol version
    {:nftables, "~> 0.4.2"}        # API version
  ]
end
```

This allows:
- Bug fixes to port without API changes
- API improvements without native code changes
- Easier maintenance and testing

#### 5. **Alternative Implementations**

The separation enables alternative execution backends:

```elixir
# Local execution via port
{:ok, pid} = NFTables.Port.start_link()
NFTables.add(table: "filter") |> NFTables.submit(pid: pid)

# Could implement remote execution without port
defmodule MyApp.RemoteRequestor do
  @behaviour NFTables.Requestor

  def submit(command, opts) do
    node = Keyword.fetch!(opts, :node)
    :rpc.call(node, NFTables.Local, :submit, [command, opts])
  end
end
```

### Port Architecture

```
NFTables.Port (GenServer)
    │
    ├─ State: %{port: port_pid, pending: %{}}
    │
    ├─ Manages: Zig port process lifecycle
    │    ├─ Spawns port with: {:spawn_executable, port_path}
    │    ├─ Packet framing: {:packet, 4} (4-byte length prefix)
    │    └─ Bidirectional communication
    │
    └─ API:
        ├─ commit(pid, json_string, timeout) → {:ok, response} | {:error, reason}
        └─ Request/response correlation via message passing
```

The port uses a simple protocol:

```
Request:  [4-byte length][JSON string]
Response: [4-byte length][JSON string]
```

**Example interaction:**

```elixir
# 1. Builder creates Elixir data structures
builder = NFTables.add(table: "filter", family: :inet)

# 2. Local requestor converts to JSON and sends to port
json = Jason.encode!(%{nftables: [%{add: %{table: %{family: :inet, name: "filter"}}}]})
{:ok, response_json} = NFTables.Port.commit(pid, json, 5000)

# 3. Port forwards to libnftables
# [Zig port] → [libnftables] → [kernel netlink] → [nftables subsystem]

# 4. Response flows back
# [kernel] → [libnftables JSON] → [Zig port] → [GenServer] → [Local]
```

---

## Core Architecture Components

### 1. NFTables (Main Module)

The entry point providing convenience functions and delegating to specialized modules:

```elixir
defmodule NFTables do
  # Process management
  defdelegate start_link(opts \\ []), to: NFTables.Port
  defdelegate stop(pid), to: GenServer

  # Dual-arity Builder API
  def add(opts), do: Builder.new(opts) |> add(opts)
  def add(%Builder{} = builder, opts), do: NFTables.add(builder, opts)

  # Policy helpers
  defdelegate allow_ssh(pid, opts \\ []), to: NFTables.Policy
  defdelegate setup_basic_firewall(pid, opts \\ []), to: NFTables.Policy
end
```

### 2. NFTables.Requestor (Behaviour)

**Responsibility:** Define the interface for submission handlers.

```elixir
defmodule NFTables.Requestor do
  @callback submit(builder :: term(), opts :: keyword()) ::
    :ok | {:ok, term()} | {:error, term()}
end
```

The Requestor behaviour allows you to define custom handlers for submitting Builder configurations. This enables use cases beyond local execution:

- **Remote execution**: Submit configurations to remote nodes
- **Audit logging**: Log all firewall changes before applying
- **Testing**: Capture configurations without applying
- **Batching**: Accumulate multiple configs before submission

### 3. NFTables.Local (Default Requestor)

**Responsibility:** Local execution requestor - the **only** place where JSON encoding/decoding happens for local execution.

```elixir
defmodule NFTables.Local do
  @behaviour NFTables.Requestor

  @doc """
  Submit command (Builder or map) for local execution by:
  1. Converting to JSON (ONLY place encoding happens)
  2. Sending to Port
  3. Receiving response JSON
  4. Decoding JSON (ONLY place decoding happens)
  5. Returning Elixir structures
  """
  @impl true
  def submit(builder_or_command, opts) do
    command = case builder_or_command do
      %{__struct__: Builder} -> Builder.to_map(builder_or_command)
      map when is_map(map) -> map
    end

    command
    |> Jason.encode!()            # → JSON string
    |> send_to_port(opts)         # → Port
    |> receive_response()         # ← JSON string
    |> Jason.decode!(keys: :atoms) # → Elixir map
    |> check_errors()
  end
end
```

**Key principle:** All other modules work with pure Elixir data structures (maps, lists, atoms, strings). JSON is an implementation detail of Local.

### 4. NFTables.Query

**Responsibility:** Build read-operation command maps (pure functions).

```elixir
defmodule NFTables.Query do
  # Pure functions that return command maps
  def list_tables(opts \\ []) do
    %{nftables: [%{list: %{tables: build_filter(opts)}}]}
  end

  def list_rules(table, chain, opts \\ []) do
    %{nftables: [%{list: %{chain: %{
      family: opts[:family] || :inet,
      table: table,
      name: chain
    }}}]}
  end
end
```

**Usage pattern (pipeline):**

```elixir
{:ok, data} = Query.list_tables(family: :inet)
  |> Local.submit(pid: pid)
  |> Decoder.decode()
```

### 5. NFTables.Decoder

**Responsibility:** Transform nftables JSON responses into idiomatic Elixir structures.

```elixir
defmodule NFTables.Decoder do
  def decode({:ok, %{nftables: items}}) do
    case detect_response_type(items) do
      :write_only -> :ok
      :read_only -> decode_read_only(items)
      :mixed -> decode_mixed(items)
    end
  end

  # Transforms this:
  # %{nftables: [%{table: %{name: "filter", family: "inet"}}]}
  #
  # Into this:
  # {:ok, %{tables: [%{name: "filter", family: :inet}]}}
end
```

### 6. NFTables.Expr

**Responsibility:** Low-level expression builders for nftables JSON structures.

```elixir
defmodule NFTables.Expr do
  # Build match expressions
  def payload_match(protocol, field, value, op \\ "==") do
    %{match: %{
      left: %{payload: %{protocol: protocol, field: field}},
      right: normalize_value(value),
      op: op
    }}
  end

  # Build statements
  def limit(rate, per, opts \\ []) do
    %{limit: %{rate: rate, per: per, burst: opts[:burst] || 0}}
  end

  # Build verdicts
  def verdict("accept"), do: %{accept: nil}
  def verdict("drop"), do: %{drop: nil}
end
```

---

## Builder Architecture

The Builder provides a unified, functional API for constructing nftables configurations.

### Design Philosophy

```elixir
# Key principles:
# 1. Pure building - immutable, no side effects
# 2. Explicit execution - commands only run when execute/2 is called
# 3. Atom keys - all internal data uses atoms (converted to strings for JSON)
# 4. Context tracking - automatically remembers table/chain/collection
# 5. Unified API - same functions (add/delete/flush) for all object types
```

### Core Structure

```elixir
defmodule NFTables.Builder do
  defstruct [
    family: :inet,         # Address family
    table: nil,            # Current table (context)
    chain: nil,            # Current chain (context)
    collection: nil,       # Current set/map (context)
    type: nil,             # Type metadata
    spec: nil,             # Current spec being built
    commands: []           # Accumulated command list
  ]
end
```

### Priority-Based Object Detection

Builder automatically detects which object type you're operating on using a **priority map**:

```elixir
@object_priority_map %{
  table: 0,       # Lowest priority = context
  chain: 1,       # Context for rules
  rule: 2,        # Main object
  rules: 2,       # (same priority as rule)
  set: 3,         # Main object
  map: 3,         # Main object
  flowtable: 3,   # Main object
  element: 4      # Highest priority
}
```

**How it works:**

```elixir
# When you write:
NFTables.add(builder, table: "filter", chain: "INPUT", rule: [...])

# Builder detects:
# - table: priority 0 (context)
# - chain: priority 1 (context)
# - rule: priority 2 (MAIN OBJECT - highest priority)
#
# Result: Adds a rule to "filter/INPUT", updating builder context for next operation
```

### Context Chaining

Builder tracks context so you don't repeat yourself:

```elixir
builder
|> NFTables.add(table: "filter", chain: "INPUT")  # Sets context
|> NFTables.add(rule: ssh_rule)                   # Uses filter/INPUT
|> NFTables.add(rule: http_rule)                  # Still uses filter/INPUT
|> NFTables.add(chain: "OUTPUT")                  # Changes chain context
|> NFTables.add(rule: outbound_rule)              # Uses filter/OUTPUT
```

### Automatic Rule Conversion

Builder automatically converts `NFTables.Expr` structs to expression lists:

```elixir
# You write:
ssh_rule = tcp() |> dport(22) |> accept()
NFTables.add(builder, rule: ssh_rule)

# Builder automatically calls:
NFTables.Expr.to_list(ssh_rule)  # → [%{match: ...}, %{accept: nil}]

# No need to call to_list() manually!
```

### Command Building Pipeline

When you call `NFTables.add(builder, opts)`, this happens:

```elixir
# Step 1: Detect main object type
{:rule, rule_value} = find_highest_priority(opts)

# Step 2: Extract context (lower priority objects)
context = extract_context(opts, :rule)
# → %{table: "filter", chain: "INPUT"}

# Step 3: Update builder with context
builder = update_builder_context(builder, context)

# Step 4: Build base spec
spec = build_spec(builder, :add, :rule, opts)
# → %{family: :inet, table: "filter", chain: "INPUT", expr: [...]}

# Step 5: Add optional fields
spec = update_spec(:rule, :add, spec, opts)
# → Adds :comment, :index, :handle if present

# Step 6: Wrap in command structure
command = %{add: %{rule: spec}}

# Step 7: Add to builder.commands list
builder = %{builder | commands: builder.commands ++ [command]}
```

### Unified API Pattern

All object types use the same functions:

```elixir
# Tables
builder |> add(table: "filter")
builder |> delete(table: "filter")
builder |> flush(table: "filter")

# Chains
builder |> add(chain: "INPUT", type: :filter, hook: :input)
builder |> delete(chain: "INPUT")
builder |> flush(chain: "INPUT")
builder |> rename(chain: "INPUT", newname: "NEW_INPUT")

# Rules
builder |> add(rule: [...])
builder |> insert(rule: [...], index: 0)
builder |> replace(rule: [...], handle: 123)
builder |> delete(rule: 123)  # Just pass handle

# Sets
builder |> add(set: "blocklist", type: :ipv4_addr)
builder |> delete(set: "blocklist")
builder |> flush(set: "blocklist")

# Elements
builder |> add(element: ["192.168.1.1"], set: "blocklist")
builder |> delete(element: ["192.168.1.1"], set: "blocklist")
```

### Execution

```elixir
# Build up commands (pure)
builder = Builder.new(family: :inet)
  |> NFTables.add(table: "filter")
  |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
  |> NFTables.add(rule: accept_established)

# Execute all at once (side effect)
NFTables.submit(builder, pid: pid)

# Internally:
# 1. Wraps commands: %{nftables: builder.commands}
# 2. Calls Local.submit/2
# 3. Local handles JSON encoding and Port communication
```

---

## Match and Rule Building

The library provides **two complementary APIs** for building rule expressions:

### 1. NFTables.Expr (Pure Functional API)

**Design:**
- Pure functions returning updated struct
- Delegation to specialized sub-modules
- Protocol-agnostic port matching
- Expression list building

**Structure:**

```elixir
defmodule NFTables.Expr do
  defstruct [
    family: :inet,
    comment: nil,
    protocol: nil,      # Tracks current protocol context
    expr_list: []       # List of expression maps
  ]

  # Core entry point
  def rule(opts \\ []), do: %__MODULE__{family: opts[:family] || :inet}

  # Delegates to sub-modules:
  defdelegate source_ip(builder, ip), to: Match.IP
  defdelegate dport(builder, port), to: Match.Port
  defdelegate tcp_flags(builder, flags, mask), to: Match.TCP
  defdelegate ct_state(builder, states), to: Match.CT
  defdelegate payload_raw(builder, base, offset, length, value), to: Match.Advanced
  defdelegate accept(builder), to: Match.Verdicts
  defdelegate snat_to(builder, ip, opts), to: Match.NAT
  defdelegate meter_update(builder, key, set, rate, per, opts), to: Match.Meter
end
```

**Sub-Module Organization:**

```
NFTables.Expr
├── Match.IP          - IP address matching
├── Match.Port        - Port matching (protocol-aware)
├── Match.TCP         - TCP-specific (flags, options)
├── Match.Layer2      - Interface, MAC, VLAN
├── Match.CT          - Connection tracking
├── Match.Advanced    - Mark, DSCP, raw payload, socket, OSF
├── Match.Protocols   - SCTP, DCCP, GRE
├── Match.Actions     - Counter, log, limit, mark operations
├── Match.Verdicts    - Accept, drop, reject, jump, etc.
├── Match.NAT         - SNAT, DNAT, masquerade, redirect
└── Match.Meter       - Dynamic sets, per-key rate limiting
```

**Protocol-Aware Port Matching:**

```elixir
# Match.Port automatically uses protocol context
expr()
|> tcp()                    # Sets protocol: :tcp
|> dport(22)                # Uses TCP protocol for port match
|> accept()

# Internally:
def tcp(builder), do: %{builder | protocol: :tcp}

def dport(builder, port) do
  protocol = case builder.protocol do
    :tcp -> "tcp"
    :udp -> "udp"
    :sctp -> "sctp"
    _ -> "tcp"  # default
  end

  expr = Expr.payload_match(protocol, "dport", port)
  add_expr(builder, expr)
end
```

**Expression List Building:**

```elixir
import NFTables.Expr

# Building a rule
ssh_rule = expr()
  |> tcp()                          # protocol: :tcp
  |> dport(22)                      # expr_list: [match tcp.dport]
  |> ct_state([:new])               # expr_list: [match tcp.dport, match ct.state]
  |> limit(10, :minute, burst: 5)   # expr_list: [match, match, limit]
  |> log("SSH: ")                   # expr_list: [match, match, limit, log]
  |> accept()                       # expr_list: [match, match, limit, log, accept]

# Each function adds to expr_list:
def add_expr(builder, expr) when is_map(expr) do
  %{builder | expr_list: builder.expr_list ++ [expr]}
end

# Extract expressions:
to_expr(ssh_rule)  # → [%{match: ...}, %{match: ...}, %{limit: ...}, %{log: ...}, %{accept: nil}]
```

### 2. NFTables.Expr (High-Level Fluent API)

**Design:**
- Simpler, more concise function names
- All functionality in one module
- No sub-module delegation
- Same expression list pattern

**Structure:**

```elixir
defmodule NFTables.Expr do
  defstruct [
    family: :inet,
    table: nil,        # Optional table context
    chain: nil,        # Optional chain context
    expr_list: [],     # Expression list
    comment: nil
  ]

  # Shorter, simpler names
  def new(opts \\ []), do: %__MODULE__{...}
  def protocol(rule, proto), do: add_expr(rule, Expr.meta_match("l4proto", proto))
  def source(rule, ip), do: add_expr(rule, Expr.payload_match("ip", "saddr", ip))
  def port(rule, port), do: dport(rule, port)
  def state(rule, states), do: add_expr(rule, Expr.ct_match("state", states))
  def accept(rule), do: add_expr(rule, Expr.verdict("accept"))
end
```

**Comparison:**

```elixir
# NFTables.Expr (verbose, explicit)
import NFTables.Expr
source_ip("10.0.0.1") |> dest_ip("192.168.1.1") |> ct_state([:new])

# NFTables.Expr (concise)
source_ip("10.0.0.1") |> dest_ip("192.168.1.1") |> ct_state([:new])

# Both produce same expr_list
```

**When to use each:**

- **Match**: More organized for large codebases, explicit naming, sub-module namespacing
- **Rule**: Quicker for small scripts, less import clutter, simpler names

---

## Composition Patterns

Both Builder and Match/Rule use functional composition patterns extensively.

### 1. Pipe-Based Composition

**Core principle:** Every function returns an updated struct, enabling chaining via `|>`.

```elixir
# Builder composition
config = Builder.new(family: :inet)
  |> NFTables.add(table: "filter")
  |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
  |> NFTables.add(chain: "FORWARD", type: :filter, hook: :forward)
  |> NFTables.add(chain: "OUTPUT", type: :filter, hook: :output)

# Match composition
ssh_rule = expr()
  |> tcp()
  |> dport(22)
  |> ct_state([:new])
  |> limit(10, :minute)
  |> accept()

# Combining both
NFTables.add(table: "filter")
  |> NFTables.add(chain: "INPUT")
  |> NFTables.add(rule: ssh_rule)
  |> NFTables.submit(pid: pid)
```

### 2. Functional Transformation

**Immutability:** Structs are never mutated, only transformed:

```elixir
# Bad (mutation - not used in library)
builder.table = "filter"

# Good (transformation - used everywhere)
builder = %{builder | table: "filter"}

# Better (helper function)
defp update_table(builder, table), do: %{builder | table: table}
```

### 3. List Accumulation

Both Builder and Match accumulate lists functionally:

```elixir
# Builder accumulates commands
defp add_command(builder, command) do
  %{builder | commands: builder.commands ++ [command]}
end

# Match accumulates expressions
defp add_expr(builder, expr) do
  %{builder | expr_list: builder.expr_list ++ [expr]}
end
```

### 4. Higher-Order Composition

Rules can be composed with `Enum` functions:

```elixir
# Generate multiple similar rules
ports = [80, 443, 8080, 8443]

rules = Enum.map(ports, fn port ->
  tcp() |> dport(port) |> accept()
end)

# Add all rules to builder
builder = Enum.reduce(rules, builder, fn rule, acc ->
  NFTables.add(acc, rule: rule)
end)

# Or use batch rules
builder |> NFTables.add(rules: rules)
```

### 5. Partial Application Patterns

Create reusable rule fragments:

```elixir
# Create base rule builder
defmodule MyFirewall.Rules do
  import NFTables.Expr

  # Partial rule - returns fn
  def with_rate_limit(rate, per) do
    fn rule -> rule |> limit(rate, per, burst: rate * 2) end
  end

  # Partial rule - returns fn
  def with_logging(prefix) do
    fn rule -> rule |> log(prefix) end
  end

  # Compose partials
  def ssh_rule do
    expr()
    |> tcp()
    |> dport(22)
    |> ct_state([:new])
    |> with_rate_limit(10, :minute).()
    |> with_logging("SSH: ").()
    |> accept()
  end
end
```

### 6. Module-Based Composition

Sub-modules compose through delegation:

```elixir
# Match.IP is a separate module
defmodule NFTables.Expr.IP do
  def source_ip(builder, ip) do
    expr = Expr.payload_match("ip", "saddr", ip)
    Match.add_expr(builder, expr)
  end
end

# Match delegates to it
defmodule NFTables.Expr do
  defdelegate source_ip(builder, ip), to: Match.IP
end

# User composes naturally
source_ip("10.0.0.1") |> dest_ip("192.168.1.1")
```

---

## Data Flow and Execution Pipeline

### Write Operation Flow

```
User Code
    ↓
NFTables.add(table: "filter")
    ↓ (accumulates Elixir maps)
Builder{commands: [%{add: %{table: %{...}}}]}
    ↓
NFTables.submit(pid: pid)
    ↓
Local.submit(builder, pid)
    ↓ (converts to JSON)
Jason.encode!(%{nftables: [...]})
    ↓
NFTables.Port.commit(pid, json, timeout)
    ↓ (sends length-prefixed packet)
Zig Port Process
    ↓ (calls libnftables)
libnftables.nft_run_cmd_from_buffer()
    ↓ (generates netlink messages)
Linux Kernel Netlink
    ↓ (applies changes)
nftables Subsystem
    ↓ (response flows back)
Local.submit/2
    ↓ (decodes JSON)
{:ok, response_map}
    ↓ (returns to user)
:ok
```

### Read Operation Flow

```
User Code
    ↓
Query.list_tables(family: :inet)
    ↓ (pure function returns map)
%{nftables: [%{list: %{tables: %{family: :inet}}}]}
    ↓
|> Local.submit(pid: pid)
    ↓ (encodes JSON, sends to port)
Port → libnftables → Kernel
    ↓ (kernel returns data)
Port → Local
    ↓ (decodes JSON)
{:ok, %{nftables: [%{table: %{...}}, ...]}}
    ↓
|> Decoder.decode()
    ↓ (transforms to idiomatic Elixir)
{:ok, %{tables: [%{name: "filter", family: :inet}]}}
    ↓
User Code
```

### Complete Example

```elixir
# 1. Build configuration (pure, no side effects)
import NFTables.Expr
alias NFTables.Builder

ssh_rule = tcp() |> dport(22) |> accept()
http_rule = tcp() |> dport(80) |> accept()

config = Builder.new(family: :inet)
  |> NFTables.add(table: "filter")
  |> NFTables.add(chain: "INPUT", type: :filter, hook: :input, policy: :drop)
  |> NFTables.add(rule: ssh_rule)
  |> NFTables.add(rule: http_rule)

# At this point:
# config.commands = [
#   %{add: %{table: %{family: :inet, name: "filter"}}},
#   %{add: %{chain: %{family: :inet, table: "filter", name: "INPUT", ...}}},
#   %{add: %{rule: %{family: :inet, table: "filter", chain: "INPUT", expr: [...]}}},
#   %{add: %{rule: %{family: :inet, table: "filter", chain: "INPUT", expr: [...]}}}
# ]

# 2. Execute (side effect - applies to kernel)
{:ok, pid} = NFTables.Port.start_link()
NFTables.submit(config, pid: pid)

# Internally:
# 1. Local.submit(%{nftables: config.commands}, pid)
# 2. Jason.encode!(...) → JSON string
# 3. NFTables.Port.commit(pid, json, 5000)
# 4. Port sends to libnftables
# 5. libnftables applies via netlink
# 6. Response flows back
# 7. Local returns :ok or {:error, reason}

# 3. Query state (read operation)
{:ok, rules} = Query.list_rules("filter", "INPUT")
  |> Local.submit(pid: pid)
  |> Decoder.decode()

# rules = %{rules: [
#   %{table: "filter", chain: "INPUT", handle: 1, expr: [...]},
#   %{table: "filter", chain: "INPUT", handle: 2, expr: [...]}
# ]}
```

---

## Requestor Pattern

The Requestor pattern provides a flexible, behaviour-based mechanism for submitting Builder configurations to custom handlers. This enables use cases beyond local execution via NFTables.Port.

### Overview

Instead of always executing locally via `NFTables.submit(builder, pid: pid)`, you can define custom "requestors" that handle submission in different ways:

```elixir
# Traditional local execution
NFTables. NFTables.add(table: "filter")
|> NFTables.submit(pid: pid)  # Goes to NFTables.Port

# Custom requestor submission
Builder.new(requestor: MyApp.RemoteRequestor)
|> NFTables.add(table: "filter")
|> NFTables.submit(node: :firewall@server)  # Goes to custom handler
```

### The NFTables.Requestor Behaviour

Requestors implement a simple behaviour with one callback:

```elixir
@callback submit(builder :: Builder.t(), opts :: keyword()) ::
  :ok | {:ok, term()} | {:error, term()}
```

### Use Cases

#### 1. Remote Execution

Submit configurations to remote nodes:

```elixir
defmodule MyApp.RemoteRequestor do
  @behaviour NFTables.Requestor

  @impl true
  def submit(builder, opts) do
    node = Keyword.fetch!(opts, :node)
    commands = Builder.to_map(builder)

    case :rpc.call(node, NFTables.Local, :execute, [commands, opts]) do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, {:remote_failure, reason}}
      {:badrpc, reason} -> {:error, {:rpc_error, reason}}
    end
  end
end

# Usage
builder = Builder.new(requestor: MyApp.RemoteRequestor)
|> NFTables.add(table: "filter")
|> NFTables.submit(node: :firewall01@datacenter)
```

#### 2. Audit Logging

Log all firewall changes before applying:

```elixir
defmodule MyApp.AuditRequestor do
  @behaviour NFTables.Requestor

  @impl true
  def submit(builder, opts) do
    audit_id = Keyword.fetch!(opts, :audit_id)
    user = Keyword.fetch!(opts, :user)

    # Log the change
    MyApp.AuditLog.record(%{
      id: audit_id,
      user: user,
      commands: Builder.to_map(builder),
      timestamp: DateTime.utc_now()
    })

    # Then execute locally
    pid = Keyword.get(opts, :pid) || Process.whereis(NFTables.Port)
    NFTables.Local.submit(Builder.to_map(builder), pid: pid)
  end
end

# Usage
builder = Builder.new(requestor: MyApp.AuditRequestor)
|> NFTables.add(table: "filter")
|> NFTables.submit(audit_id: UUID.generate(), user: "admin")
```

#### 3. Testing/Capture

Capture configurations without applying:

```elixir
defmodule MyApp.CaptureRequestor do
  @behaviour NFTables.Requestor

  @impl true
  def submit(builder, _opts) do
    # Send to test process for inspection
    send(self(), {:nftables_config, builder})
    :ok
  end
end

# In tests
test "builds correct firewall config" do
  builder = Builder.new(requestor: MyApp.CaptureRequestor)
  |> NFTables.add(table: "filter")
  |> NFTables.add(chain: "INPUT")
  |> NFTables.submit()

  assert_received {:nftables_config, builder}
  assert length(builder.commands) == 2
end
```

#### 4. Conditional/Environment-Based Execution

Different strategies per environment:

```elixir
defmodule MyApp.SmartRequestor do
  @behaviour NFTables.Requestor

  @impl true
  def submit(builder, opts) do
    case Application.get_env(:my_app, :env) do
      :prod -> execute_with_approval(builder, opts)
      :staging -> execute_with_logging(builder, opts)
      :dev -> log_only(builder, opts)
    end
  end

  defp execute_with_approval(builder, opts) do
    # Require manual approval in production
    MyApp.ApprovalSystem.request_approval(builder)
    |> case do
      :approved -> execute_locally(builder, opts)
      :denied -> {:error, :approval_denied}
    end
  end

  defp execute_with_logging(builder, opts) do
    Logger.info("Applying firewall changes: #{inspect(builder)}")
    execute_locally(builder, opts)
  end

  defp log_only(builder, _opts) do
    IO.inspect(builder, label: "Would apply")
    :ok
  end

  defp execute_locally(builder, opts) do
    pid = Keyword.get(opts, :pid) || Process.whereis(NFTables.Port)
    NFTables.Local.submit(Builder.to_map(builder), pid: pid)
  end
end
```

### Builder Integration

The requestor field is integrated into the Builder struct:

```elixir
defstruct family: :inet,
          requestor: nil,      # New field
          table: nil,
          chain: nil,
          collection: nil,
          type: nil,
          spec: nil,
          commands: []
```

### Three Ways to Set Requestor

#### 1. At Builder Creation

```elixir
builder = Builder.new(family: :inet, requestor: MyApp.RemoteRequestor)
```

#### 2. Via set_requestor/2

```elixir
builder = NFTables.add(table: "filter")
|> Builder.set_requestor(MyApp.AuditRequestor)
```

#### 3. Override at Submit Time

```elixir
builder = Builder.new(requestor: MyApp.DefaultRequestor)
|> NFTables.add(table: "filter")
|> NFTables.submit(requestor: MyApp.SpecialRequestor, priority: :high)
```

### Submit Functions

#### submit/1 - Use Builder's Requestor

```elixir
builder = Builder.new(requestor: MyApp.RemoteRequestor)
|> NFTables.add(table: "filter")
|> NFTables.submit()  # Uses MyApp.RemoteRequestor with empty opts
```

Raises `ArgumentError` if no requestor is configured.

#### submit/2 - With Options or Override

```elixir
# Pass options to requestor
builder |> NFTables.submit(node: :remote_host, timeout: 10_000)

# Override requestor
builder |> NFTables.submit(requestor: MyApp.SpecialRequestor, opt: "value")

# Use without pre-configured requestor
NFTables. NFTables.add(table: "filter")
|> NFTables.submit(requestor: MyApp.TestRequestor)
```

### Validation

The `submit/2` function validates that the requestor module:
- Is an atom (module name)
- Exports `submit/2` function

```elixir
# This will raise ArgumentError
NFTables.submit(builder, requestor: NonExistentModule)
# => "Module NonExistentModule does not implement NFTables.Requestor behaviour"
```

### Comparison: execute/2 vs submit/2

| Feature | execute/2 | submit/2 |
|---------|-----------|----------|
| **Target** | Local NFTables.Port (pid required) | Custom requestor module |
| **Flexibility** | Fixed: always calls libnftables | Fully customizable handler |
| **Configuration** | Pass pid | Pass requestor module |
| **Use Cases** | Direct local firewall changes | Remote, testing, audit, conditional |
| **Options** | `pid:`, `timeout:` | Requestor-specific (any opts) |
| **Return** | `:ok \| {:error, reason}` | `:ok \| {:ok, result} \| {:error, reason}` |

Both approaches can coexist in the same codebase:

```elixir
# Local execution for immediate changes
NFTables. NFTables.add(table: "filter")
|> NFTables.submit(pid: pid)

# Remote execution for distributed deployments
Builder.new(requestor: MyApp.RemoteRequestor)
|> NFTables.add(table: "filter")
|> NFTables.submit(node: :firewall@remote)
```

### Design Rationale

1. **Behaviour-Based**: Uses Elixir behaviours for compile-time contract checking
2. **Optional**: Requestor field defaults to `nil`, maintaining backward compatibility
3. **Runtime Validation**: Validates `submit/2` export at runtime for flexibility
4. **Mirrors execute/2**: Familiar pattern for users
5. **Options Passthrough**: Opts go directly to requestor for maximum flexibility

### Example: Multi-Node Firewall Deployment

```elixir
defmodule MyApp.ClusterRequestor do
  @behaviour NFTables.Requestor

  @impl true
  def submit(builder, opts) do
    nodes = Keyword.get(opts, :nodes, [:firewall01, :firewall02, :firewall03])
    strategy = Keyword.get(opts, :strategy, :parallel)

    case strategy do
      :parallel -> apply_parallel(builder, nodes)
      :serial -> apply_serial(builder, nodes)
      :canary -> apply_canary(builder, nodes)
    end
  end

  defp apply_parallel(builder, nodes) do
    commands = Builder.to_map(builder)

    results = Task.async_stream(nodes, fn node ->
      :rpc.call(node, NFTables.Local, :execute, [commands, []])
    end)
    |> Enum.to_list()

    case Enum.all?(results, fn {:ok, {:ok, _}} -> true; _ -> false end) do
      true -> {:ok, :all_nodes_updated}
      false -> {:error, :some_nodes_failed}
    end
  end

  # ... other strategies
end

# Usage
builder = Builder.new(requestor: MyApp.ClusterRequestor)
|> NFTables.add(table: "filter")
|> NFTables.add(chain: "INPUT")
|> NFTables.add(rule: block_rule)
|> NFTables.submit(strategy: :canary, nodes: [:fw01, :fw02, :fw03])
```

---

## Design Principles

### 1. **Separation of Concerns**

Each module has a single, well-defined responsibility:

- **Builder**: Accumulate configuration commands
- **Match/Rule**: Build rule expressions
- **Local, Requestor**: Handle JSON and Port communication
- **Query**: Build read commands
- **Decoder**: Transform responses
- **Expr**: Low-level expression builders
- **Port**: Manage native process lifecycle

### 2. **Pure Functions by Default**

Most functions are pure (no side effects):

```elixir
# Pure - returns new struct
NFTables.add(builder, table: "filter")

# Pure - returns new struct
tcp() |> dport(22)

# Pure - returns command map
Query.list_tables(family: :inet)

# Side effect - only when explicitly called
NFTables.submit(builder, pid: pid)
```

### 3. **Composition Over Inheritance**

The library uses functional composition instead of OOP inheritance:

```elixir
# Not classes with inheritance
# But functions that compose

expr()
  |> tcp()                 # Adds protocol context
  |> dport(22)             # Adds port match
  |> ct_state([:new])      # Adds state match
  |> accept()              # Adds verdict
```

### 4. **Explicit Over Implicit**

Behavior is explicit and predictable:

```elixir
# Explicit execution
NFTables.submit(builder, pid: pid)  # Clear when side effects occur

# Explicit conversion (though now automatic)
to_expr(rule)  # Clear when format changes

# Explicit family
Builder.new(family: :inet6)  # No hidden defaults
```

### 5. **Data-Driven Architecture**

Configuration is just data until executed:

```elixir
# Just data structures
config = NFTables.add(table: "filter")

# Can be inspected
IO.inspect(config.commands)

# Can be serialized
json = Builder.to_json(config)

# Can be tested without side effects
assert length(config.commands) == 1

# Only becomes "real" when executed
NFTables.submit(config, pid: pid)
```

### 6. **Progressive Disclosure**

Multiple API levels for different needs:

```elixir
# Level 1: High-level convenience (easiest)
NFTables.allow_ssh(pid)
NFTables.setup_basic_firewall(pid)

# Level 2: Builder + Match (flexible)
ssh_rule = tcp() |> dport(22) |> accept()
NFTables.add(rule: ssh_rule) |> NFTables.submit(pid: pid)

# Level 3: Direct expression building (full control)
expr = Expr.payload_match("tcp", "dport", 22)
NFTables.add(builder, rule: [expr, Expr.verdict("accept")])

# Level 4: Raw JSON (maximum control)
json = ~s({"nftables":[{"add":{"rule":{...}}}]})
Local.submit(Jason.decode!(json), pid: pid)
```

### 7. **Fail Fast, Fail Clearly**

Errors are caught early with clear messages:

```elixir
# Invalid priority combination
NFTables.add(builder, set: "s1", map: "m1")
# ** (ArgumentError) Ambiguous object: only use one of [:set, :map, ...]

# Missing required field
NFTables.add(builder, rule: [...])  # No table/chain context
# ** (ArgumentError) table must be specified as an option or set via set_table/2

# Invalid command/object combination
NFTables.flush(builder, element: [...])
# ** (ArgumentError) Command :flush is not valid for :element. Valid commands: add, delete
```

---

## Summary

The NFTables library architecture is built on:

1. **Isolated Port Process** - Fault isolation, security boundary, technology isolation
2. **Layered Design** - Clear boundaries between native/Elixir, pure/effectful code
3. **Functional Composition** - Immutable data structures, pure functions, pipe operators
4. **Unified APIs** - Builder for all objects, Match/Rule for expressions
5. **Data-Driven** - Configuration is data until explicitly executed
6. **Progressive Disclosure** - Multiple abstraction levels for different needs

This architecture provides a robust, maintainable, and user-friendly interface to Linux nftables while maintaining safety, testability, and flexibility.
