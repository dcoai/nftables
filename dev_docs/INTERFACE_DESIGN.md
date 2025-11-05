# NFTex Interface Design Analysis

## Current Interface: Low-Level C-Style

### How It Works Today

The current NFTex interface is a **direct mapping** of the C libnftnl API to Elixir. It exposes low-level resource management to the caller.

#### Example: Creating a Table

```elixir
# Current low-level interface
{:ok, pid} = NFTex.start_link()

# Step 1: Allocate a table resource
{:ok, table_id} = NFTex.table_alloc(pid)

# Step 2: Set attributes one by one
:ok = NFTex.table_set_str(pid, table_id, :name, "filter")
:ok = NFTex.table_set_u32(pid, table_id, :family, 2)  # AF_INET

# Step 3: Use the table (e.g., send to kernel via netlink)
# ... netlink operations ...

# Step 4: Must manually free the resource
:ok = NFTex.table_free(pid, table_id)
```

#### Example: Creating a Rule with Expressions

```elixir
# Even more complex with nested resources
{:ok, rule_id} = NFTex.rule_alloc(pid)
:ok = NFTex.rule_set_str(pid, rule_id, :table, "filter")
:ok = NFTex.rule_set_str(pid, rule_id, :chain, "input")
:ok = NFTex.rule_set_u32(pid, rule_id, :family, 2)

# Create counter expression
{:ok, counter_id} = NFTex.expr_alloc(pid, "counter")

# Create payload expression for IP source
{:ok, payload_id} = NFTex.expr_alloc(pid, "payload")
:ok = NFTex.expr_set_u32(pid, payload_id, :base, 1)      # NETWORK_HEADER
:ok = NFTex.expr_set_u32(pid, payload_id, :offset, 12)   # IP src offset
:ok = NFTex.expr_set_u32(pid, payload_id, :len, 4)
:ok = NFTex.expr_set_u8(pid, payload_id, :dreg, 1)

# Create comparison expression
{:ok, cmp_id} = NFTex.expr_alloc(pid, "cmp")
:ok = NFTex.expr_set_u32(pid, cmp_id, :op, 0)  # EQ
:ok = NFTex.expr_set_u8(pid, cmp_id, :sreg, 1)
:ok = NFTex.expr_set_data(pid, cmp_id, :data, <<192, 168, 1, 100>>)

# Create verdict expression
{:ok, verdict_id} = NFTex.expr_alloc(pid, "verdict")
:ok = NFTex.expr_set_u32(pid, verdict_id, :verdict, 0)  # DROP

# Add expressions to rule
:ok = NFTex.rule_add_expr(pid, rule_id, payload_id)
:ok = NFTex.rule_add_expr(pid, rule_id, cmp_id)
:ok = NFTex.rule_add_expr(pid, rule_id, counter_id)
:ok = NFTex.rule_add_expr(pid, rule_id, verdict_id)

# Must manually free all resources (in reverse order!)
:ok = NFTex.expr_free(pid, counter_id)
:ok = NFTex.expr_free(pid, payload_id)
:ok = NFTex.expr_free(pid, cmp_id)
:ok = NFTex.expr_free(pid, verdict_id)
:ok = NFTex.rule_free(pid, rule_id)
```

### Problems with Current Design

1. **Manual Memory Management**
   - User must remember to free every allocated resource
   - Forgetting to free causes memory leaks
   - Must free in correct order (expressions before rules)

2. **Verbose and Error-Prone**
   - 30+ lines of code to create a simple rule
   - Easy to make mistakes in attribute setting
   - No validation until runtime

3. **Imperative Style**
   - Not idiomatic Elixir
   - Mutating state with setters feels un-functional
   - No clear separation of data and behavior

4. **Resource ID Management**
   - User must track resource IDs
   - No type safety (all IDs are integers)
   - Easy to mix up table_id vs expr_id

5. **No Cleanup on Error**
   - If any step fails, previously allocated resources may leak
   - User must implement complex error handling

6. **C Library Leaking Through**
   - Magic numbers (family: 2, op: 0, etc.)
   - Low-level concepts (registers, offsets, etc.)
   - libnftnl implementation details exposed

## Proposed Interface: High-Level Elixir-Style

### Design Principles

1. **Declarative over Imperative**
   - Describe *what* you want, not *how* to build it
   - Use Elixir data structures (maps, keywords)

2. **Automatic Resource Management**
   - Zig handles alloc/free internally
   - Resources cleaned up automatically
   - No resource IDs exposed to Elixir

3. **Functional API**
   - Immutable data structures
   - Operations return results, not side effects
   - Composable primitives

4. **Type Safety**
   - Use atoms and structs instead of magic numbers
   - Clear types for different concepts

5. **Error Handling**
   - Comprehensive validation before Zig call
   - Clear error messages
   - No partial state on failure

### Proposed High-Level API

#### Example 1: Creating a Table

```elixir
# Proposed high-level interface
{:ok, pid} = NFTex.start_link()

result = NFTex.create_table(pid, %{
  name: "filter",
  family: :inet,  # Atom instead of magic number
  flags: []
})

case result do
  :ok -> IO.puts("Table created")
  {:error, reason} -> IO.puts("Failed: #{reason}")
end
```

**Behind the scenes in Zig:**
1. Allocate table
2. Set all attributes
3. Build netlink message
4. Send to kernel
5. Free table resource
6. Return result to Elixir

#### Example 2: Creating a Rule

```elixir
# Proposed high-level interface - declarative rule definition
NFTex.create_rule(pid, %{
  table: "filter",
  chain: "input",
  family: :inet,
  expressions: [
    # Match IP source address
    {:payload, :ipv4, :saddr, into: :reg1},
    {:cmp, :eq, :reg1, <<192, 168, 1, 100>>},

    # Count matching packets
    {:counter},

    # Drop the packet
    {:verdict, :drop}
  ]
})
```

**Or even simpler with a helper:**

```elixir
NFTex.block_ip(pid, "filter", "input", "192.168.1.100")
```

#### Example 3: Creating a Set with Elements

```elixir
# Current (low-level)
{:ok, set_id} = NFTex.set_alloc(pid)
:ok = NFTex.set_set_str(pid, set_id, :name, "banned_ips")
:ok = NFTex.set_set_str(pid, set_id, :table, "filter")
:ok = NFTex.set_set_u32(pid, set_id, :family, 2)
:ok = NFTex.set_set_u32(pid, set_id, :key_type, 7)
:ok = NFTex.set_set_u32(pid, set_id, :key_len, 4)

# Add elements
for ip <- banned_ips do
  {:ok, elem_id} = NFTex.set_elem_alloc(pid)
  :ok = NFTex.set_elem_set_data(pid, elem_id, :key, ip)
  :ok = NFTex.set_elem_add(pid, set_id, elem_id)
  # Note: elem_id now owned by set, don't free
end

# Send to kernel...
:ok = NFTex.set_free(pid, set_id)

# Proposed (high-level)
NFTex.create_set(pid, %{
  name: "banned_ips",
  table: "filter",
  family: :inet,
  key_type: :ipv4_addr,
  elements: [
    <<192, 168, 1, 100>>,
    <<192, 168, 1, 101>>,
    <<192, 168, 1, 102>>
  ]
})
```

### Implementation Strategy

#### Layer Architecture

```
┌─────────────────────────────────────────┐
│   High-Level Elixir API (NFTex)         │  ← New layer
│   - create_table/2                       │
│   - create_rule/2                        │
│   - create_set/2                         │
│   - block_ip/4, etc.                     │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Mid-Level Elixir API (NFTex.Low)      │  ← Keep for advanced users
│   - table_alloc/1                        │
│   - table_set_str/4                      │
│   - rule_add_expr/3                      │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Port Protocol (NFTex.Port)            │  ← Existing
│   - call/3                               │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Zig Command Handlers                  │  ← Existing (42 handlers)
│   - handleTableAlloc                     │
│   - handleTableSetStr                    │
│   - handleRuleAddExpr                    │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   New Zig High-Level Handlers           │  ← New layer in Zig
│   - handleCreateTable                    │
│   - handleCreateRule                     │
│   - handleCreateSet                      │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   libnftnl C Library                     │
└─────────────────────────────────────────┘
```

#### Option 1: High-Level Handlers in Zig (Recommended)

Add new command handlers in Zig that handle complete operations:

**New Zig commands:**
- `create_table` - Takes all table attributes, handles alloc/set/free
- `create_rule` - Takes rule definition, builds expressions internally
- `create_set` - Takes set definition with elements

**Benefits:**
- Resource management stays in Zig (safer)
- Single request/response (more efficient)
- Atomic operations (all or nothing)
- Can use Zig's error handling

**Example implementation in Zig:**

```zig
fn handleCreateTable(
    allocator: std.mem.Allocator,
    request: protocol.Request,
    resource_mgr: *resources.ResourceManager,
) !protocol.Response {
    // Parse args: {name, family, flags?}
    const name = extractString(request.args, "name") catch |err| {
        return errorResponse(allocator, request.req_id,
            try std.fmt.allocPrint(allocator, "create_table: missing name: {}", .{err}));
    };

    const family = extractU32(request.args, "family") catch |err| {
        return errorResponse(allocator, request.req_id,
            try std.fmt.allocPrint(allocator, "create_table: invalid family: {}", .{err}));
    };

    // Allocate table
    const table = libnftnl.tableAlloc() catch |err| {
        return errorResponse(allocator, request.req_id,
            try std.fmt.allocPrint(allocator, "create_table: alloc failed: {}", .{err}));
    };
    defer libnftnl.tableFree(table);  // Auto cleanup!

    // Set attributes
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);
    libnftnl.tableSetStr(table, libnftnl.NFTNL_TABLE_NAME, name_z);
    libnftnl.tableSetU32(table, libnftnl.NFTNL_TABLE_FAMILY, family);

    // Build and send netlink message
    var buf: [4096]u8 = undefined;
    const nlh = libnftnl.nlmsgBuildHdr(&buf, libnftnl.NFT_MSG_NEWTABLE,
        @intCast(family), libnftnl.NLM_F_REQUEST | libnftnl.NLM_F_ACK, 0);
    libnftnl.tableNlmsgBuildPayload(nlh, table);

    // Send to kernel (TODO: actual netlink socket code)
    // const result = sendNetlink(buf, ...);

    // Table resource freed automatically by defer
    return okResponse(allocator, request.req_id);
}
```

#### Option 2: High-Level Elixir Wrapper (Alternative)

Keep Zig low-level, add Elixir wrapper that calls multiple low-level functions:

**Benefits:**
- Easier to implement (pure Elixir)
- More flexible (can change without recompiling Zig)
- Better suited for complex logic

**Drawbacks:**
- Multiple round-trips to Zig port
- Still exposes resource management to Elixir layer
- Less efficient

**Example:**

```elixir
defmodule NFTex do
  # High-level API
  def create_table(pid, %{name: name, family: family}) do
    with {:ok, table_id} <- table_alloc(pid),
         :ok <- table_set_str(pid, table_id, :name, name),
         :ok <- table_set_u32(pid, table_id, :family, family_to_int(family)),
         :ok <- send_table_to_kernel(pid, table_id),
         :ok <- table_free(pid, table_id) do
      :ok
    else
      {:error, reason} = error ->
        # Cleanup on error
        table_free(pid, table_id)
        error
    end
  end

  # Low-level API (existing)
  defdelegate table_alloc(pid), to: NFTex.Port
  defdelegate table_set_str(pid, id, attr, value), to: NFTex.Port
  # ...
end
```

#### Hybrid Approach (Best of Both)

1. **Add high-level Zig handlers for common operations**
   - `create_table`, `create_chain`, `create_rule`, `create_set`
   - Handle alloc/free internally
   - Return success/failure only

2. **Keep low-level API available**
   - For advanced users and custom operations
   - Expose as `NFTex.Low.*` namespace
   - Document as "advanced API"

3. **Add Elixir helpers for domain logic**
   - `block_ip/4`, `allow_port/4`, etc.
   - Compose high-level Zig operations
   - Handle application-specific logic

### Migration Path

#### Phase 1: Add High-Level Zig Handlers
- Implement `handleCreateTable`, `handleCreateChain`, `handleCreateRule`
- Keep existing low-level handlers
- No breaking changes

#### Phase 2: Add High-Level Elixir API
- Add `NFTex.create_table/2`, etc.
- Move existing API to `NFTex.Low.*`
- Document both APIs

#### Phase 3: Add Elixir Helpers
- Add `NFTex.Helpers.block_ip/4`, etc.
- Build on high-level API
- Examples and documentation

#### Phase 4: Deprecation (Optional)
- Mark low-level API as advanced/deprecated
- Encourage high-level API usage
- Keep low-level for backward compatibility

## Comparison Examples

### Example: Block an IP Address

#### Current Low-Level API (35+ lines)

```elixir
{:ok, pid} = NFTex.start_link()

# Create rule
{:ok, rule_id} = NFTex.rule_alloc(pid)
:ok = NFTex.rule_set_str(pid, rule_id, :table, "filter")
:ok = NFTex.rule_set_str(pid, rule_id, :chain, "input")
:ok = NFTex.rule_set_u32(pid, rule_id, :family, 2)

# Create payload expression
{:ok, payload_id} = NFTex.expr_alloc(pid, "payload")
:ok = NFTex.expr_set_u32(pid, payload_id, :base, 1)
:ok = NFTex.expr_set_u32(pid, payload_id, :offset, 12)
:ok = NFTex.expr_set_u32(pid, payload_id, :len, 4)
:ok = NFTex.expr_set_u8(pid, payload_id, :dreg, 1)

# Create comparison expression
{:ok, cmp_id} = NFTex.expr_alloc(pid, "cmp")
:ok = NFTex.expr_set_u32(pid, cmp_id, :op, 0)
:ok = NFTex.expr_set_u8(pid, cmp_id, :sreg, 1)
:ok = NFTex.expr_set_data(pid, cmp_id, :data, ip_to_binary("192.168.1.100"))

# Create verdict expression
{:ok, verdict_id} = NFTex.expr_alloc(pid, "verdict")
:ok = NFTex.expr_set_u32(pid, verdict_id, :verdict, 0)

# Add expressions to rule
:ok = NFTex.rule_add_expr(pid, rule_id, payload_id)
:ok = NFTex.rule_add_expr(pid, rule_id, cmp_id)
:ok = NFTex.rule_add_expr(pid, rule_id, verdict_id)

# Send to kernel...

# Cleanup (easy to forget!)
:ok = NFTex.expr_free(pid, payload_id)
:ok = NFTex.expr_free(pid, cmp_id)
:ok = NFTex.expr_free(pid, verdict_id)
:ok = NFTex.rule_free(pid, rule_id)
```

#### Proposed High-Level API (3 lines)

```elixir
{:ok, pid} = NFTex.start_link()

NFTex.block_ip(pid, "filter", "input", "192.168.1.100")
```

Or with more control:

```elixir
NFTex.create_rule(pid, %{
  table: "filter",
  chain: "input",
  family: :inet,
  expressions: [
    {:match, :ipv4, :saddr, "192.168.1.100"},
    {:verdict, :drop}
  ]
})
```

## Recommendations

### Immediate Next Steps

1. **Start with one high-level handler in Zig**
   - Implement `handleCreateTable` as proof of concept
   - Test memory management (alloc/defer/free)
   - Validate the approach

2. **Design the protocol**
   - Define how complex data (maps, lists) are passed
   - Use ETF's map and list support
   - Document the encoding

3. **Add high-level Elixir wrapper**
   - `NFTex.create_table/2` wrapping new handler
   - Clean API with validation
   - Good error messages

4. **Document both APIs**
   - High-level API for common use
   - Low-level API for advanced use
   - Migration guide

### Long-Term Vision

**NFTex becomes:**
- **Safe**: No memory leaks, automatic cleanup
- **Idiomatic**: Feels like Elixir, not C
- **Powerful**: Low-level access when needed
- **Productive**: Common tasks are simple

**Example of the dream API:**

```elixir
# Start NFTex
{:ok, nft} = NFTex.start_link()

# Create a complete firewall in one call
NFTex.configure(nft, """
  table inet filter {
    chain input {
      type filter hook input priority 0; policy accept;

      # Allow established connections
      ct state established,related accept

      # Allow localhost
      iif lo accept

      # Allow SSH
      tcp dport 22 accept

      # Block specific IPs
      ip saddr { 192.168.1.100, 192.168.1.101 } drop

      # Rate limit
      limit rate 10/second accept
    }
  }
""")
```

This would be parsed in Elixir and compiled to low-level operations in Zig, with all resource management handled automatically.
