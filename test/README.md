# NFTex Test Suite

Comprehensive test suite for NFTex nftables bindings.

## Prerequisites

### 1. CAP_NET_ADMIN Capability

Tests require the port binary to have `CAP_NET_ADMIN` capability:

```bash
# For the main port (recommended):
sudo setcap cap_net_admin=ep priv/port_nftables
getcap priv/port_nftables  # Verify

# Or for other ports:
sudo setcap cap_net_admin=ep priv/port_nftables
sudo setcap cap_net_admin=ep priv/port_nftables
```

### 2. nftables Infrastructure (for integration tests)

Some tests require existing nftables infrastructure:

```bash
# Create filter table
sudo nft add table filter

# Create INPUT chain for rule tests
sudo nft add chain filter INPUT '{ type filter hook input priority 0; }'

# Create test set for set operation tests
sudo nft add set filter test_blocklist '{ type ipv4_addr; }'
```

## Running Tests

### Run All Tests

```bash
mix test
```

### Run Specific Test File

```bash
mix test test/nftables/rule_test.exs
mix test test/nftables/query_test.exs
mix test test/nftables/set_operations_test.exs
mix test test/nftables/policy_test.exs
```

### Run Tests with Tags

```bash
# Run only tests marked as :integration
mix test --only integration

# Run tests marked :requires_chain (needs filter/INPUT to exist)
mix test --only requires_chain

# Run tests marked :requires_set (needs test_blocklist set to exist)
mix test --only requires_set

# Exclude tests that need specific infrastructure
mix test --exclude requires_chain --exclude requires_set
```

### Run Tests with Trace

```bash
# See detailed output for each test
mix test --trace
```

### Run Specific Test by Line Number

```bash
mix test test/nftables/rule_test.exs:22
```

## Test Organization

### High-Level API Tests

Located in `test/nftables/`:

- **rule_test.exs** - Tests for NFTex.Rule
  - `block_ip/4` - Blocking IP addresses
  - `accept_ip/4` - Allowing IP addresses
  - `list/4` - Listing rules in chains
  - Integration workflows

- **query_test.exs** - Tests for NFTex.Query (currently disabled)
  - `list_tables/2` - Query tables
  - `list_chains/2` - Query chains
  - `list_rules/2` - Query rules
  - `list_sets/2` - Query sets
  - `list_set_elements/3` - Query set elements

- **set_operations_test.exs** - Tests for NFTex.Set
  - `add_elements/5` - Add IPs to sets
  - `delete_elements/5` - Remove IPs from sets
  - `list_elements/3` - List set contents
  - `exists?/4` - Check if set exists
  - `list/2` - List all sets

- **policy_test.exs** - Tests for NFTex.Policy
  - Pre-built firewall policies
  - Security baseline configurations

### Port Tests

Located in `test/nftables/`:

- **json_port_test.exs** - JSON port communication tests
- **etf_port_test.exs** - ETF port communication tests
- **port_test.exs** - Port format detection tests

## Test Tags

Tests use ExUnit tags for categorization:

- `:integration` - All tests (requires CAP_NET_ADMIN)
- `:requires_chain` - Tests needing filter/INPUT chain
- `:requires_set` - Tests needing test_blocklist set

## Test Status

### ✅ Fully Tested

- **NFTex.Port** - Format detection and communication
- **NFTex.Port** - JSON string communication
- **NFTex.Port** - ETF term communication
- **NFTex.Policy** - Pre-built firewall policies

### 🚧 Partial Coverage

- **NFTex.Rule** - Basic functionality tested
- **NFTex.Query** - Currently disabled, needs updates for v0.4.0
- **NFTex.Set** - Basic operations tested
- **NFTex.Table** - Table operations tested
- **NFTex.Chain** - Chain operations tested

### 📋 Planned

- **Integration test suite** - End-to-end firewall scenarios
- **Error handling** - Edge cases and error conditions
- **Performance** - Benchmarking and stress tests

## Continuous Integration

For CI environments:

1. **Without kernel access** - Run only unit tests:
   ```bash
   mix test --exclude integration
   ```

2. **With kernel access** - Run all tests:
   ```bash
   # Setup infrastructure
   sudo setcap cap_net_admin=ep priv/port_nftables  # or port_nftables, port_nftables
   sudo nft add table filter
   sudo nft add chain filter INPUT '{ type filter hook input priority 0; }'
   sudo nft add set filter test_blocklist '{ type ipv4_addr; }'

   # Run tests
   mix test
   ```

## Troubleshooting

### "Operation not permitted" errors

Ensure CAP_NET_ADMIN is set:
```bash
sudo setcap cap_net_admin=ep priv/port_nftables  # or port_nftables, port_nftables
```

### "No such file or directory" for tables/chains

Create the required infrastructure (see Prerequisites above).

### "Process not alive" errors

This is normal - tests clean up processes after each test. The test framework handles this correctly.

### Tests timing out

Increase timeout if needed:
```bash
mix test --timeout 60000  # 60 seconds
```

## Writing New Tests

Template for new test files:

```elixir
Code.require_file("../test_helper.exs", __DIR__)

defmodule YourModuleTest do
  use ExUnit.Case
  require Logger

  @moduletag :integration

  describe "your feature" do
    setup do
      {:ok, pid} = NFTex.start_link()
      on_exit(fn ->
        if Process.alive?(pid) do
          NFTex.stop(pid)
        end
      end)
      {:ok, pid: pid}
    end

    test "does something", %{pid: pid} do
      # Your test here
      assert true
    end
  end
end
```

## Test Coverage

Generate coverage report:

```bash
mix test --cover
```

View detailed coverage:

```bash
mix test --cover
open cover/excoveralls.html
```

## Contributing

When adding new features:

1. Add tests in `test/nftables/` for high-level APIs
2. Add tests in `test/` root for low-level operations
3. Use appropriate tags (`:integration`, `:requires_chain`, etc.)
4. Document any prerequisites in test comments
5. Ensure tests clean up resources properly
6. Run full test suite before submitting PR

## Resources

- [ExUnit Documentation](https://hexdocs.pm/ex_unit/ExUnit.html)
- [ExUnit.Case](https://hexdocs.pm/ex_unit/ExUnit.Case.html)
- [Testing Best Practices](https://hexdocs.pm/phoenix/testing.html)
