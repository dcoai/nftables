# Developer Documentation

This directory contains comprehensive documentation about NFTables internals and architecture.

## Documentation Files

### Architecture & Design

1. **[RULE_BUILDER_ARCHITECTURE.md](RULE_BUILDER_ARCHITECTURE.md)**
   - Complete explanation of how Match works
   - Pure functional expression builder pattern
   - Module organization and delegation
   - Execution flow from builder to kernel via Local
   - Benefits and design philosophy
   - Extension points for adding features

2. **[NFT_SYNTAX_VS_JSON.md](NFT_SYNTAX_VS_JSON.md)**
   - Explanation of JSON expression building
   - How Match generates nftables JSON expressions
   - Builder Pattern separation pattern
   - Why pure functional is better than execution-coupled design

3. **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)**
   - Quick lookup guide for common patterns
   - Visual flow diagrams
   - Complex rule examples with explanations
   - Actions vs Verdicts reference
   - Architecture summary

4. **[REFERENCE.md](REFERENCE.md)**
   - Comprehensive API reference documentation

### Examples & Output

5. **[COMPLEX_RULE_EXAMPLES_OUTPUT.txt](COMPLEX_RULE_EXAMPLES_OUTPUT.txt)**
   - Live output from complex rule examples
   - Shows actual JSON generated

6. **[QUERY_BUILDER_OUTPUT.txt](QUERY_BUILDER_OUTPUT.txt)**
   - Live output from Query builder functions
   - Shows JSON generated for query operations

## Quick Navigation

### Want to understand how Match works?
→ Start with **[RULE_BUILDER_ARCHITECTURE.md](RULE_BUILDER_ARCHITECTURE.md)**

### Need to see examples of complex rules?
→ Check **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** or **[COMPLEX_RULE_EXAMPLES_OUTPUT.txt](COMPLEX_RULE_EXAMPLES_OUTPUT.txt)**

### Looking for common patterns?
→ See **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)**

### Want to understand the JSON format?
→ Read **[NFT_SYNTAX_VS_JSON.md](NFT_SYNTAX_VS_JSON.md)**

### Need to build query commands?
→ Check **[QUERY_BUILDER_OUTPUT.txt](QUERY_BUILDER_OUTPUT.txt)** for examples

## Advanced Features

NFTables includes comprehensive support for advanced nftables capabilities:

- **Flowtables** - Hardware-accelerated packet forwarding
- **Meters/Dynamic Sets** - Per-key rate limiting with composite keys
- **Raw Payload Matching** - Offset-based packet inspection for custom protocols
- **Socket Matching & TPROXY** - Transparent proxy support
- **SCTP/DCCP/GRE** - Specialized protocol matching
- **OSF (OS Fingerprinting)** - Passive OS detection

See [ADVANCED_FEATURES_COMPLETE.md](../ADVANCED_FEATURES_COMPLETE.md) and individual phase summaries for complete documentation.

## Key Concepts

### Pure Functional Match API

Match is now a **pure expression builder** with no side effects:

```elixir
import NFTables.Match
alias NFTables.{Builder, Local, Requestor}

# Build pure expression
expr = rule()
  |> tcp()
  |> dport(22)
  |> accept()

# Execute separately
Builder.new()
|> Builder.add(rule: expr, table: "filter", chain: "INPUT", family: :inet)
|> Local.submit(pid)
```

### Builder Pattern Separation

Clear separation between building and executing:
- **Match** - Builds pure expression data
- **Builder** - Constructs complete nftables configurations
- **Local, Requestor** - Handle configuration submission to kernel or custom handlers

### JSON Expression Building

Match generates JSON expression lists:
```elixir
expr = rule()
  |> source_ip("192.168.1.100")
  |> tcp()
  |> dport(22)
  |> accept()

# Returns: [%{match: ...}, %{match: ...}, %{accept: nil}]
```

## Example: SSH Protection Rule

**Code:**
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

**Generated JSON:**
```json
{
  "nftables": [{
    "add": {
      "rule": {
        "family": "inet",
        "table": "filter",
        "chain": "INPUT",
        "expr": [
          {"match": {"left": {"payload": {"protocol": "tcp"}}}},
          {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
          {"match": {"left": {"ct": {"key": "state"}}, "right": ["new"]}},
          {"limit": {"rate": 5, "per": "minute", "burst": 10}},
          {"log": {"prefix": "SSH_RATELIMIT: ", "level": "warn"}},
          {"drop": null}
        ]
      }
    }
  }]
}
```

## Architecture Summary

```
High-Level API (Match, Policy, NAT)
    ↓
Pure Expression Building (JSON expressions)
    ↓
Builder (Constructs configuration)
    ↓
Local (JSON encoding/decoding)
    ↓
NFTables.Port (GenServer)
    ↓
Erlang Port (C/Zig executable)
    ↓
libnftables (JSON API)
    ↓
Netlink Messages
    ↓
Linux Kernel (nf_tables)
```

## Total Documentation

- **6 documents** covering architecture, examples, and reference
- Comprehensive coverage of new Match API
- Live examples with actual output
- Visual diagrams showing data flow

## Contributing

When adding new features:
1. Update appropriate architecture docs
2. Add examples to QUICK_REFERENCE.md with new API
3. Include live examples in output files
4. Ensure documentation reflects pure functional design
