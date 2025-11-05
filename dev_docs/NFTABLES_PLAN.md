# NFTex: Elixir Interface to nftables via libnftnl

## Project Overview

Build a port-based Elixir interface to Linux nftables using the libnftnl library, implemented in Zig.

## Architecture Decision Record

### Approach: Port vs NIF
**Decision:** Port-based implementation
**Rationale:**
- Fault isolation (port crashes don't crash BEAM VM)
- No scheduler blocking concerns for potentially blocking netlink operations
- Better security isolation
- Easier debugging and testing

### Protocol: ETF (Erlang External Term Format)
**Decision:** Use ETF with ei.h library
**Rationale:**
- Official Erlang C library (`ei.h`) provides mature, thread-safe ETF encoding/decoding
- Native integration with BEAM
- Zig has excellent C interop
- No need to implement custom serialization

### Privilege Management: Linux Capabilities
**Decision:** Use CAP_NET_ADMIN capability
**Rationale:**
- More secure than running as root
- Principle of least privilege
- Can drop other privileges after startup
- Standard approach for netfilter userspace tools

### API Level: Low-Level Only
**Decision:** Expose raw libnftnl API
**Rationale:**
- Maximum flexibility for users
- Users can build their own abstractions
- Simpler initial implementation
- Easier to maintain API compatibility with libnftnl

## System Architecture

```
┌─────────────────────────────────────────┐
│         Elixir Application              │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │   NFTex (Public API Module)       │ │
│  │   - Low-level libnftnl wrappers   │ │
│  └──────────────┬────────────────────┘ │
│                 │                       │
│  ┌──────────────▼────────────────────┐ │
│  │   NFTex.Port (GenServer)          │ │
│  │   - Port lifecycle management     │ │
│  │   - ETF encode/decode (Elixir)    │ │
│  │   - Request/response correlation  │ │
│  └──────────────┬────────────────────┘ │
└─────────────────┼──────────────────────┘
                  │ Erlang Port (ETF)
┌─────────────────▼──────────────────────┐
│  Zig Port Process (libnf_ex)           │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │   Main Loop (stdin/stdout)        │ │
│  └──────────────┬────────────────────┘ │
│                 │                       │
│  ┌──────────────▼────────────────────┐ │
│  │   Protocol Handler (ei.h)         │ │
│  │   - ETF decode/encode             │ │
│  └──────────────┬────────────────────┘ │
│                 │                       │
│  ┌──────────────▼────────────────────┐ │
│  │   Command Dispatcher              │ │
│  └──────────────┬────────────────────┘ │
│                 │                       │
│  ┌──────────────▼────────────────────┐ │
│  │   Resource Manager                │ │
│  │   - Tracks libnftnl objects       │ │
│  │   - Lifecycle management          │ │
│  └──────────────┬────────────────────┘ │
│                 │                       │
│  ┌──────────────▼────────────────────┐ │
│  │   libnftnl C Library Wrapper      │ │
│  └──────────────┬────────────────────┘ │
└─────────────────┼──────────────────────┘
                  │ Netlink
┌─────────────────▼──────────────────────┐
│      Linux Kernel (nf_tables)          │
└────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Foundation Setup
- [ ] 1.1. Initialize Zig project structure
  - [ ] Create `native/` directory
  - [ ] Set up `build.zig` with dependencies (nftnl, mnl, ei, cap)
  - [ ] Configure include paths for ei.h
- [ ] 1.2. Set up Elixir project structure
  - [ ] Create module structure (NFTex, NFTex.Port, NFTex.Supervisor)
  - [ ] Configure Mix to compile Zig project
  - [ ] Set up supervision tree
- [ ] 1.3. Verify dependencies
  - [ ] Install libnftnl-dev
  - [ ] Install libmnl-dev
  - [ ] Install erlang-dev (for ei.h)
  - [ ] Install libcap-dev
  - [ ] Verify Zig installation

### Phase 2: Basic Port Communication
- [ ] 2.1. Implement Zig port skeleton
  - [ ] `src/main.zig` - Entry point with stdin/stdout loop
  - [ ] `src/capabilities.zig` - Capability setup/teardown
  - [ ] Test port startup and capability configuration
- [ ] 2.2. Implement ETF protocol layer
  - [ ] `src/protocol.zig` - ei.h wrappers
  - [ ] Message reading from stdin
  - [ ] Response writing to stdout
  - [ ] Error handling
- [ ] 2.3. Implement Elixir port manager
  - [ ] `lib/nftex/port.ex` - GenServer for port management
  - [ ] Port spawning with packet mode
  - [ ] Request/response correlation
  - [ ] Timeout handling
- [ ] 2.4. Test basic communication
  - [ ] Ping/pong test
  - [ ] Version query test
  - [ ] Error handling test

### Phase 3: Resource Management
- [ ] 3.1. Implement resource manager in Zig
  - [ ] `src/resources.zig` - ResourceManager struct
  - [ ] Resource ID allocation
  - [ ] Resource storage (HashMap)
  - [ ] Resource cleanup on free
- [ ] 3.2. Implement libnftnl bindings
  - [ ] `src/libnftnl.zig` - C bindings
  - [ ] Import libnftnl headers
  - [ ] Wrap allocation functions
  - [ ] Wrap free functions

### Phase 4: Table Operations
- [ ] 4.1. Implement table operations in Zig
  - [ ] `nftnl_table_alloc` wrapper
  - [ ] `nftnl_table_free` wrapper
  - [ ] `nftnl_table_set_str` wrapper
  - [ ] `nftnl_table_set_u32` wrapper
  - [ ] `nftnl_table_get_str` wrapper
  - [ ] `nftnl_table_get_u32` wrapper
- [ ] 4.2. Add command dispatcher entries
  - [ ] `src/commands.zig` - Command routing
  - [ ] Define opcodes for table operations
  - [ ] Implement command handlers
- [ ] 4.3. Implement Elixir API
  - [ ] `lib/nftex.ex` - Table functions
  - [ ] `table_alloc/1`
  - [ ] `table_free/2`
  - [ ] `table_set_str/4`
  - [ ] `table_set_u32/4`
  - [ ] `table_get_str/3`
  - [ ] `table_get_u32/3`
- [ ] 4.4. Write tests
  - [ ] Create/free table test
  - [ ] Set/get table name test
  - [ ] Set/get table family test

### Phase 5: Chain Operations
- [ ] 5.1. Implement chain operations in Zig
  - [ ] Allocation/free functions
  - [ ] String attribute setters/getters
  - [ ] Numeric attribute setters/getters
  - [ ] Hook configuration
- [ ] 5.2. Implement Elixir API
  - [ ] Chain allocation functions
  - [ ] Chain attribute functions
  - [ ] Hook setup functions
- [ ] 5.3. Write tests
  - [ ] Create/free chain test
  - [ ] Chain attributes test
  - [ ] Base chain with hook test

### Phase 6: Rule Operations
- [ ] 6.1. Implement rule operations in Zig
  - [ ] Allocation/free functions
  - [ ] Attribute setters/getters
  - [ ] Expression management
- [ ] 6.2. Implement Elixir API
  - [ ] Rule allocation functions
  - [ ] Rule attribute functions
  - [ ] Add expression to rule
- [ ] 6.3. Write tests
  - [ ] Create/free rule test
  - [ ] Rule attributes test

### Phase 7: Expression Operations
- [ ] 7.1. Implement expression operations in Zig
  - [ ] Expression allocation by name
  - [ ] Expression free
  - [ ] Generic attribute setters
  - [ ] Data setters for binary data
- [ ] 7.2. Implement Elixir API
  - [ ] `expr_alloc/2`
  - [ ] `expr_free/2`
  - [ ] `expr_set_u8/4`, `expr_set_u16/4`, `expr_set_u32/4`, `expr_set_u64/4`
  - [ ] `expr_set_str/4`
  - [ ] `expr_set_data/4` (for binary data)
- [ ] 7.3. Write tests
  - [ ] Common expressions (payload, cmp, immediate, counter)
  - [ ] Expression attribute setting

### Phase 8: Set Operations
- [ ] 8.1. Implement set operations in Zig
  - [ ] Allocation/free functions
  - [ ] Attribute setters/getters
  - [ ] Element management
- [ ] 8.2. Implement Elixir API
  - [ ] Set allocation functions
  - [ ] Set attribute functions
  - [ ] Set element functions
- [ ] 8.3. Write tests
  - [ ] Create/free set test
  - [ ] Set with elements test

### Phase 9: Batch & Netlink Operations
- [ ] 9.1. Implement batch operations in Zig
  - [ ] Batch allocation/free
  - [ ] Batch begin/end
  - [ ] Message building (nlmsg_build_hdr)
  - [ ] Payload building for each object type
- [ ] 9.2. Implement netlink communication
  - [ ] Open netlink socket (using libmnl)
  - [ ] Send batch to kernel
  - [ ] Receive responses
  - [ ] Parse netlink errors
- [ ] 9.3. Implement Elixir API
  - [ ] Batch functions
  - [ ] Message building functions
  - [ ] Send/receive functions
- [ ] 9.4. Write integration tests
  - [ ] Create table in kernel
  - [ ] Create chain in kernel
  - [ ] Add rule in kernel
  - [ ] Query existing rules
  - [ ] Delete rules/chains/tables

### Phase 10: Error Handling & Robustness
- [ ] 10.1. Comprehensive error handling
  - [ ] Map libnftnl errors to Elixir errors
  - [ ] Map netlink errors to descriptive messages
  - [ ] Resource cleanup on errors
- [ ] 10.2. Logging and debugging
  - [ ] Add structured logging in Zig
  - [ ] Add debug logging in Elixir
  - [ ] Add trace mode for protocol debugging
- [ ] 10.3. Resource leak prevention
  - [ ] Automatic cleanup on port exit
  - [ ] Resource reference counting
  - [ ] Orphan resource detection

### Phase 11: Documentation
- [ ] 11.1. API documentation
  - [ ] Document all Elixir functions with @doc
  - [ ] Add @spec for all public functions
  - [ ] Add usage examples
- [ ] 11.2. Guides
  - [ ] Installation guide
  - [ ] Capability setup guide
  - [ ] Basic usage guide
  - [ ] Advanced usage guide (batching, sets, etc.)
- [ ] 11.3. Reference documentation
  - [ ] libnftnl attribute mapping
  - [ ] Expression types and attributes
  - [ ] Error codes and meanings

### Phase 12: Testing & Validation
- [ ] 12.1. Unit tests
  - [ ] Test all Elixir functions
  - [ ] Test error conditions
  - [ ] Test resource lifecycle
- [ ] 12.2. Integration tests
  - [ ] Test against real kernel
  - [ ] Test complex rule creation
  - [ ] Test batch operations
  - [ ] Test concurrent operations
- [ ] 12.3. Property-based tests
  - [ ] Resource allocation/free cycles
  - [ ] Attribute setting/getting roundtrips
- [ ] 12.4. Performance tests
  - [ ] Batch operation throughput
  - [ ] Large ruleset handling
  - [ ] Memory usage profiling

## Dependencies

### System Requirements
- Linux kernel >= 3.14 (nf_tables support)
- libnftnl >= 1.1.5
- libmnl >= 1.0.4
- libcap >= 2.25
- Erlang/OTP >= 24 (for ei.h)

### Build Dependencies
- Zig >= 0.11.0
- Elixir >= 1.14
- Development headers for all system libraries

### Elixir Dependencies
- usage_rules - For structured logging and telemetry

### Runtime Requirements
- CAP_NET_ADMIN capability for port binary
- Read access to /proc/sys/net/netfilter/

## API Surface

### Core Functions

```elixir
# Connection
NFTex.start_link(opts) :: {:ok, pid()}
NFTex.stop(pid()) :: :ok

# Table operations
NFTex.table_alloc(pid()) :: {:ok, resource_id()}
NFTex.table_free(pid(), resource_id()) :: :ok
NFTex.table_set_str(pid(), resource_id(), attr, value) :: :ok
NFTex.table_set_u32(pid(), resource_id(), attr, value) :: :ok
NFTex.table_get_str(pid(), resource_id(), attr) :: {:ok, String.t()}
NFTex.table_get_u32(pid(), resource_id(), attr) :: {:ok, integer()}

# Chain operations
NFTex.chain_alloc(pid()) :: {:ok, resource_id()}
NFTex.chain_free(pid(), resource_id()) :: :ok
NFTex.chain_set_str(pid(), resource_id(), attr, value) :: :ok
NFTex.chain_set_u32(pid(), resource_id(), attr, value) :: :ok
NFTex.chain_set_u8(pid(), resource_id(), attr, value) :: :ok
NFTex.chain_get_str(pid(), resource_id(), attr) :: {:ok, String.t()}
NFTex.chain_get_u32(pid(), resource_id(), attr) :: {:ok, integer()}

# Rule operations
NFTex.rule_alloc(pid()) :: {:ok, resource_id()}
NFTex.rule_free(pid(), resource_id()) :: :ok
NFTex.rule_set_str(pid(), resource_id(), attr, value) :: :ok
NFTex.rule_set_u32(pid(), resource_id(), attr, value) :: :ok
NFTex.rule_set_u64(pid(), resource_id(), attr, value) :: :ok
NFTex.rule_add_expr(pid(), rule_id, expr_id) :: :ok

# Expression operations
NFTex.expr_alloc(pid(), name) :: {:ok, resource_id()}
NFTex.expr_free(pid(), resource_id()) :: :ok
NFTex.expr_set_u8(pid(), resource_id(), attr, value) :: :ok
NFTex.expr_set_u16(pid(), resource_id(), attr, value) :: :ok
NFTex.expr_set_u32(pid(), resource_id(), attr, value) :: :ok
NFTex.expr_set_u64(pid(), resource_id(), attr, value) :: :ok
NFTex.expr_set_str(pid(), resource_id(), attr, value) :: :ok
NFTex.expr_set_data(pid(), resource_id(), attr, binary) :: :ok

# Set operations
NFTex.set_alloc(pid()) :: {:ok, resource_id()}
NFTex.set_free(pid(), resource_id()) :: :ok
NFTex.set_set_str(pid(), resource_id(), attr, value) :: :ok
NFTex.set_set_u32(pid(), resource_id(), attr, value) :: :ok
NFTex.set_elem_add(pid(), set_id, elem_id) :: :ok

# Batch operations
NFTex.batch_alloc(pid()) :: {:ok, resource_id()}
NFTex.batch_free(pid(), resource_id()) :: :ok
NFTex.batch_begin(pid(), batch_id, seq) :: :ok
NFTex.batch_end(pid(), batch_id, seq) :: :ok
NFTex.nlmsg_build_hdr(pid(), buf, type, flags, seq, portid, family) :: {:ok, binary()}
NFTex.table_nlmsg_build_payload(pid(), buf, table_id) :: {:ok, binary()}
NFTex.chain_nlmsg_build_payload(pid(), buf, chain_id) :: {:ok, binary()}
NFTex.rule_nlmsg_build_payload(pid(), buf, rule_id) :: {:ok, binary()}
NFTex.set_nlmsg_build_payload(pid(), buf, set_id) :: {:ok, binary()}
NFTex.batch_send(pid(), batch_id) :: :ok
NFTex.recv(pid(), timeout) :: {:ok, binary()}
```

## File Structure

```
iptex/
├── lib/
│   ├── nftex.ex                  # Main public API
│   └── nftex/
│       ├── port.ex               # Port GenServer
│       └── supervisor.ex         # Supervision tree
├── native/                       # Zig port implementation
│   ├── build.zig
│   └── src/
│       ├── main.zig             # Entry point
│       ├── protocol.zig         # ETF protocol (ei.h)
│       ├── commands.zig         # Command dispatcher
│       ├── resources.zig        # Resource manager
│       ├── capabilities.zig     # Linux capabilities
│       ├── libnftnl.zig         # C bindings
│       └── errors.zig           # Error handling
├── test/
│   ├── nftex_test.exs           # API tests
│   └── integration_test.exs     # Integration tests
├── priv/
│   └── libnf_ex                 # Compiled binary (generated)
├── mix.exs
└── NFTABLES_PLAN.md             # This file
```

## Testing Strategy

### Unit Tests
- Test each Elixir function in isolation
- Mock port responses for deterministic tests
- Test error conditions and edge cases

### Integration Tests
- Require root/CAP_NET_ADMIN to run
- Test against actual kernel nf_tables
- Create/query/delete operations
- Verify changes in kernel

### Property Tests
- Use StreamData for property-based testing
- Test invariants (alloc -> free should not leak)
- Test attribute roundtrips (set -> get)

## Security Considerations

1. **Capability Isolation**: Port runs with only CAP_NET_ADMIN
2. **No New Privileges**: prctl(PR_SET_NO_NEW_PRIVS) prevents privilege escalation
3. **Non-dumpable**: Prevents ptrace attacks
4. **Input Validation**: All inputs validated before passing to libnftnl
5. **Resource Limits**: Prevent resource exhaustion attacks
6. **Error Messages**: Don't leak sensitive information in errors

## Performance Considerations

1. **Batch Operations**: Group multiple changes into single netlink transaction
2. **Resource Pooling**: Consider resource pooling for frequent alloc/free
3. **Binary Protocol**: ETF is compact and efficient
4. **Port Communication**: Packet mode (4-byte length prefix) for framing
5. **Concurrent Requests**: Support multiple in-flight requests

## Future Enhancements (Out of Scope)

- [ ] Higher-level DSL for rule creation
- [ ] Rule parsing/pretty-printing
- [ ] NFT JSON format support
- [ ] Live rule monitoring/events
- [ ] Rule performance statistics
- [ ] NIF version for hot-path operations
- [ ] Connection tracking helpers
- [ ] NAT helpers

## References

- [libnftnl Documentation](https://netfilter.org/projects/libnftnl/)
- [nftables Wiki](https://wiki.nftables.org/)
- [Erlang ei.h Documentation](https://www.erlang.org/doc/man/ei.html)
- [Linux capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Zig Language Reference](https://ziglang.org/documentation/master/)
