# NFTex Project - Current State

**Last Updated:** 2025-11-05
**Status:** Active Development - Debugging Set Operations

---

## Project Overview

NFTex is an Elixir library providing native bindings to nftables (Linux kernel firewall) via libnftnl. It uses a Zig-based native port process to communicate with the kernel through netlink sockets.

**Architecture:**
- Elixir → Port → Zig binary → libnftnl (C library) → Netlink → Linux kernel (nftables)

---

## Current Status

### Test Results
- **Total Tests:** ~120 tests
- **Current Failures:** 84 failures (reduced from original 97)
- **Main Issue:** Set operations failing with `EINVAL` (-22) error

### Recent Progress

Successfully reduced test failures from 97 to 84 by fixing:

1. **Family Mapping Issue** (Fixed)
   - Problem: `:inet` was incorrectly mapped to `2` (NFPROTO_IPV4) instead of `1` (NFPROTO_INET)
   - Impact: Rules couldn't find their parent chains due to family mismatch
   - Files fixed:
     - `lib/nftex/rule_builder.ex:328`
     - `lib/nftex/set.ex:274`
     - `lib/nftex/expression_builder.ex:927`

2. **Netlink Flag Issues** (Fixed)
   - Problem 1: `NLM_F_APPEND` was being applied to ALL resources (sets, tables, chains, rules)
   - Solution: Only apply `NLM_F_APPEND` to rules (they append to chains)
   - File: `native/src/commands/common.zig:196-202`

   - Problem 2: Missing `NLM_F_REQUEST` flag on all kernel communications
   - Solution: Added `NLM_F_REQUEST` flag which is mandatory for all netlink messages to kernel
   - File: `native/src/commands/common.zig:196`

3. **Test Infrastructure** (Fixed)
   - Problem: Set operation tests were trying to add elements to non-existent sets
   - Solution: Added proper set creation in all test setup blocks using `NFTex.Kernel.Set` API
   - File: `test/nftex/set_operations_test.exs` (5 describe blocks updated)

---

## Active Problem: Set Creation Fails with EINVAL

### Symptoms
When creating sets, the kernel returns `{:error, -22}` (EINVAL - Invalid argument).

```elixir
# This fails:
{:ok, set_id} = NFTex.Kernel.Set.alloc(pid)
:ok = NFTex.Kernel.Set.set_str(pid, set_id, :table, "nftex_test_debug")
:ok = NFTex.Kernel.Set.set_str(pid, set_id, :name, "test_set")
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :family, 1)  # NFPROTO_INET
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_type, 7)  # NFT_DATA_VALUE
:ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_len, 4)  # 4 bytes for IPv4
result = NFTex.Kernel.Set.send_to_kernel(pid, set_id, :add)
# Returns: {:error, -22}
```

### What Works
- Tables create successfully
- Chains create successfully
- `nft` command can create sets: `sudo nft add set inet test_table test_set '{ type ipv4_addr; }'`

### Current Theory

The EINVAL error suggests we're still missing required netlink attributes or using incorrect values. The most recent fix (adding `NLM_F_REQUEST`) was critical but hasn't been fully tested yet due to capability/permission issues.

**Potential causes:**
1. ✅ Missing `NLM_F_REQUEST` flag (just fixed, needs testing)
2. ❓ Incorrect `key_type` value (using 7, but might need different constant)
3. ❓ Missing mandatory set attributes (flags, policy, etc.)
4. ❓ Incorrect netlink message structure for sets specifically

---

## Technical Details

### Protocol Family Constants
```
NFPROTO_INET    = 1   # Dual-stack IPv4+IPv6 (correct for :inet)
NFPROTO_IPV4    = 2   # IPv4 only (correct for :ip)
NFPROTO_IPV6    = 10  # IPv6 only (correct for :ip6)
```

### Netlink Message Flags
```
NLM_F_REQUEST   = 1      # REQUIRED for all kernel messages
NLM_F_ACK       = 4      # Request acknowledgment
NLM_F_CREATE    = 1024   # Create if doesn't exist
NLM_F_APPEND    = 2048   # Append to chain (ONLY for rules!)
```

### Set Attributes Currently Set
```elixir
:table      => "table_name"    # NFTNL_SET_TABLE (0)
:name       => "set_name"      # NFTNL_SET_NAME (1)
:family     => 1               # NFTNL_SET_FAMILY (7)
:key_type   => 7               # NFTNL_SET_KEY_TYPE (3) - possibly wrong?
:key_len    => 4               # NFTNL_SET_KEY_LEN (4)
```

### Available Set Attributes (Not Used)
```
NFTNL_SET_FLAGS       (2)   # Set flags
NFTNL_SET_DATA_TYPE   (5)   # For maps
NFTNL_SET_DATA_LEN    (6)   # For maps
NFTNL_SET_ID          (8)   # Set ID
NFTNL_SET_POLICY      (9)   # Set policy
NFTNL_SET_DESC_SIZE   (10)  # Size hint
```

### Key Type Mystery

The code uses `key_type = 7` for IPv4 addresses, but kernel headers show:
```c
enum nft_data_types {
    NFT_DATA_VALUE = 0,
    NFT_DATA_VERDICT = 0xffffff00U,
};
```

The comment in kernel headers states: "all values are equivalent to NFT_DATA_VALUE" but the actual type might need to be specified differently. The `nft` command uses `type ipv4_addr` but this might translate to a different constant than what we're using.

---

## Current Plan

### Immediate Next Steps

1. **Test NLM_F_REQUEST Fix** ⏳
   - Need to set capabilities: `sudo setcap cap_net_admin=ep priv/libnf_ex`
   - Run test: `mix run /tmp/test_set_creation.exs`
   - **Expected:** This should fix the EINVAL error
   - **If fails:** Move to step 2

2. **Investigate key_type Constants** (If step 1 fails)
   - Compare with nftables source code to find correct type constants
   - Check if `key_type=7` is correct for IPv4 addresses
   - May need to use NFT_DATA_VALUE (0) instead
   - Resources:
     - `/usr/include/linux/netfilter/nf_tables.h`
     - nftables source: https://git.netfilter.org/nftables/

3. **Add Missing Mandatory Attributes** (If step 2 fails)
   - Investigate if sets require `flags` or `policy` attributes
   - Check libnftnl examples or nftables source for minimum required attributes
   - Add any missing attributes to set creation

4. **Compare with Working nft Command**
   - Capture netlink traffic from `nft add set` command using strace or similar
   - Compare attributes and message structure with our implementation
   - Identify differences

### After Set Creation Works

5. **Run Full Test Suite**
   - Verify all 84 remaining failures are resolved
   - Identify any new categories of failures

6. **Address Policy Function Issues**
   - Tests for policy functions were also failing
   - May be related to chain creation or different issue

7. **Verify Set Element Operations**
   - Once sets create successfully, verify add/delete/list element operations work
   - These use different netlink messages (NFT_MSG_NEWSETELEM, etc.)

---

## Alternative Approaches

If the current debugging approach stalls, consider:

### 1. **Minimal Working Example from libnftnl**
- Find or write a minimal C program using libnftnl that creates a set
- Compare its exact netlink messages with ours
- Replicate its exact approach in Zig

### 2. **Use nftables JSON API**
- nftables supports JSON for all operations
- Could bypass libnftnl entirely
- Trade-off: More parsing overhead, less control

### 3. **Netlink Traffic Capture**
- Use `strace -f -e trace=sendto,recvfrom` on working `nft` command
- Capture exact bytes sent to kernel
- Compare with our netlink messages byte-by-byte

### 4. **Kernel Debug Logging**
- Enable nftables kernel debugging: `echo 1 > /sys/kernel/debug/dynamic_debug/control`
- Check dmesg for detailed error messages from kernel
- May reveal exactly which validation is failing

---

## Build & Test Commands

### Rebuild Native Binary
```bash
cd native && zig build
chmod 750 ../priv/libnf_ex
sudo setcap cap_net_admin=ep ../priv/libnf_ex
```

### Run Tests
```bash
# Full test suite
mix test

# Specific test file
mix test test/nftex/set_operations_test.exs

# Single test with line number
mix test test/nftex/set_operations_test.exs:50

# With trace
mix test --trace
```

### Test Scripts
- `/tmp/test_set_creation.exs` - Basic set creation test
- `/tmp/test_set_ip_family.exs` - Tests with :ip family instead of :inet

---

## Known Issues

1. **Binary Permissions Reset on Recompile**
   - After each `zig build`, permissions reset to 755 and capabilities are cleared
   - Must manually run: `chmod 750 && sudo setcap cap_net_admin=ep`
   - Could add post-build hook in mix.exs

2. **Background Test Processes**
   - Multiple test runs were started in background and may still be running
   - Check with: `ps aux | grep mix`
   - Kill if needed: `pkill -f "mix test"`

3. **Capability Checks**
   - Binary refuses to start if world-readable (security feature)
   - Checks for CAP_NET_ADMIN capability before starting
   - Location: `native/src/main.zig:45`

---

## Important Files

### Core Implementation
- `native/src/commands/common.zig` - Netlink message building (where flags are set)
- `native/src/commands/set.zig` - Set operations handler
- `native/src/libnftnl.zig` - C bindings to libnftnl
- `lib/nftex/set.ex` - High-level Elixir set API
- `lib/nftex/kernel/set.ex` - Low-level kernel set operations

### Tests
- `test/nftex/set_operations_test.exs` - Set operation tests (main failing tests)
- `test/nftex/integration_test.exs` - Integration tests
- `test/nftex/policy_test.exs` - Policy tests (also failing)
- `test/nftex/rule_test.exs` - Rule tests

### Documentation
- `CLAUDE.md` - Project instructions for LLM assistance
- `CHANGELOG.md` - Change history
- `SECURITY.md` - Security considerations
- `CURRENT_STATE.md` - This file

---

## References

### Kernel Documentation
- nftables netlink spec: https://docs.kernel.org/networking/netlink_spec/nftables.html
- Kernel headers: `/usr/include/linux/netfilter/nf_tables.h`

### Libraries
- libnftnl: https://www.netfilter.org/projects/libnftnl/
- nftables source: https://git.netfilter.org/nftables/

### Previous Work
- Git history shows 3 commits:
  - `980d188` - dev updates
  - `5ca579e` - added better error messages
  - `fa182b7` - initial revision

---

## Next Session Recommendations

1. **First Priority:** Test if `NLM_F_REQUEST` flag fix resolves the EINVAL error
   - This is the most likely cause
   - Set capabilities and run test script

2. **If Still Failing:** Investigate key_type values
   - May need to use 0 (NFT_DATA_VALUE) or different constant
   - Check kernel source for proper type encoding

3. **Consider Alternative:** Capture and compare netlink traffic
   - Use strace on working `nft` command
   - Compare with our implementation
   - This gives definitive answer about what kernel expects

---

## Questions to Investigate

1. What is the correct value for `key_type` for IPv4 addresses?
   - Currently using 7
   - Kernel headers suggest 0 (NFT_DATA_VALUE) for all data types
   - Need to check how nft encodes "ipv4_addr"

2. Are there mandatory set attributes beyond what we're setting?
   - Do sets require `flags` attribute?
   - Do sets require `policy` attribute?
   - Do sets require `desc_size` for size hints?

3. Why does `key_type=7` work for set elements but not set creation?
   - Set element operations use this value successfully
   - But set creation with same value fails
   - Suggests different semantics for set vs element attributes

---

**Status Summary:** We've made significant progress fixing fundamental issues (family mappings, netlink flags). The remaining EINVAL error is likely due to the missing `NLM_F_REQUEST` flag that was just added but not yet tested due to capability issues. Once capabilities are set and tests run, we should see if sets now create successfully.
