# NFTables Usage Rules

## Overview

NFTables provides a pure functional API for building nftables firewall rules via Elixir.

---

## Core Principles

### 1. Pure Functional Expression API

Build expressions as **pure data** with **no side effects**.

```elixir
import NFTables.Expr

# Build expression (no side effects)
rule = tcp() |> dport(22) |> accept()

# Execute separately
{:ok, pid} = NFTables.Port.start_link()

NFTables.add(table: "filter", family: :inet)
|> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
|> NFTables.add(rule: rule)
|> NFTables.submit(pid: pid)
```

### 2. Build/Submit Separation

- **NFTables.Expr** - Builds pure expression data (no execution)
- **NFTables** - Constructs nftables configurations (no execution)
- **NFTables.submit** - Sends configurations to kernel (execution only)

### 3. Dual-Arity Functions

```elixir
tcp() |> dport(22) |> accept()               # Start new
expr() |> tcp() |> dport(22) |> accept()     # Continue existing
```

### 4. Context Tracking

NFTables automatically tracks table/chain context:

```elixir
NFTables.add(table: "filter", chain: "INPUT")
|> NFTables.add(rule: tcp() |> dport(22) |> accept())
|> NFTables.add(rule: tcp() |> dport(80) |> accept())
```

---

## Key Modules

**NFTables** - Main API: `add/1-2`, `delete/1-2`, `flush/1-2`, `submit/1-2`

**NFTables.Expr** - Expression builder: `tcp/0-1`, `udp/0-1`, `dport/1-2`, `state/1-2`, `accept/0-1`, `drop/0-1`, `log/0-2`

**NFTables.Port** - Process management: `start_link/0-1`, `stop/1`

**NFTables.Policy** - Pre-built policies: `accept_loopback/1`, `accept_established/1`, `allow_ssh/1-2`

---

## Expression Building

### Protocol and Port Matching

```elixir
import NFTables.Expr

tcp() |> dport(80) |> accept()              # Single port
udp() |> dport(53) |> accept()              # UDP
tcp() |> dport({8000, 8999}) |> accept()    # Port range
tcp() |> dport([80, 443, 8080]) |> accept() # Multiple ports
```

### State Tracking

```elixir
state([:established, :related]) |> accept()   # Accept established
ct_state([:invalid]) |> drop()                 # Drop invalid
ct_state([:new]) |> log() |> accept()          # Log new
```

### Actions and Verdicts

```elixir
# Terminal verdicts (end processing)
accept()   # Accept packet
drop()     # Silently drop
reject()   # Reject with ICMP

# Non-terminal actions (continue processing)
counter() |> log("SSH") |> accept()           # Chain actions
limit(rate: "10/minute") |> accept()          # Rate limiting
```

---

## Common Patterns

### Basic Firewall

```elixir
import NFTables.Expr
{:ok, pid} = NFTables.Port.start_link()

NFTables.add(table: "filter", family: :inet)
|> NFTables.add(chain: "INPUT", type: :filter, hook: :input, policy: :drop)
|> NFTables.add(rule: state([:established, :related]) |> accept())
|> NFTables.add(rule: tcp() |> dport(22) |> accept())
|> NFTables.submit(pid: pid)
```

### SSH with Rate Limiting

```elixir
rule = tcp() |> dport(22) |> limit(rate: "10/minute") |> accept()

NFTables.add(table: "filter", chain: "INPUT")
|> NFTables.add(rule: rule)
|> NFTables.submit(pid: pid)
```

### Multiple Rules in Batch

```elixir
rules = [
  tcp() |> dport(22) |> accept(),
  tcp() |> dport(80) |> accept(),
  tcp() |> dport(443) |> accept()
]

NFTables.add(table: "filter", chain: "INPUT")
|> NFTables.add(rules: rules)
|> NFTables.submit(pid: pid)
```

### Using Policy Module

```elixir
NFTables.add(table: "filter")
|> NFTables.add(chain: "INPUT", type: :filter, hook: :input, policy: :drop)
|> Policy.accept_loopback()
|> Policy.accept_established()
|> Policy.allow_ssh(rate_limit: 10)
|> NFTables.submit(pid: pid)
```

---

## Best Practices

### 1. Import NFTables.Expr

```elixir
import NFTables.Expr  # Always import for concise code
rule = tcp() |> dport(22) |> accept()
```

### 2. Use Context Tracking

```elixir
# Good - context tracked automatically
NFTables.add(table: "filter", chain: "INPUT")
|> NFTables.add(rule: rule1)
|> NFTables.add(rule: rule2)
```

### 3. Build Expressions as Data

```elixir
ssh_rule = tcp() |> dport(22) |> accept()
http_rule = tcp() |> dport(80) |> accept()

NFTables.add(table: "filter", chain: "INPUT")
|> NFTables.add(rule: ssh_rule)
|> NFTables.add(rule: http_rule)
|> NFTables.submit(pid: pid)
```

### 4. Test Without Side Effects

```elixir
rule = tcp() |> dport(22) |> accept()
assert %NFTables.Expr{} = rule  # Test without kernel access
NFTables.add(table: "filter", chain: "INPUT")
|> NFTables.add(rule: rule)
|> NFTables.submit(pid: pid)
```

### 5. Clean Up in Tests

```elixir
setup do
  {:ok, pid} = NFTables.Port.start_link()
  on_exit(fn ->
    NFTables.delete(table: "test") |> NFTables.submit(pid: pid)
    NFTables.Port.stop(pid)
  end)
  {:ok, pid: pid}
end
```

---

## Anti-Patterns

### ❌ Don't Use Builder Directly

```elixir
Builder.new() |> Builder.apply_with_opts(:add, table: "filter")  # Bad
NFTables.add(table: "filter")                                     # Good
```

### ❌ Don't Repeat Context

```elixir
NFTables.add(table: "filter", chain: "INPUT", rule: rule1)       # Bad
NFTables.add(table: "filter", chain: "INPUT") |> add(rule: r1)  # Good
```

### ❌ Don't Mix Side Effects with Building

```elixir
def build_rule(pid), do: NFTables.add(...) |> submit(pid: pid)  # Bad
def build_rule, do: tcp() |> dport(22) |> accept()              # Good
```

---

## See Also

- **README.md** - Main documentation
- **Module docs** - `h NFTables`, `h NFTables.Expr`, `h NFTables.Policy`
- **dev_docs/** - Architecture, quick reference, advanced features
- **examples/** - Working code examples
