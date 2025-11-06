# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### In Progress
- CI/CD pipeline configuration
- Performance benchmarking

## [0.4.0] - 2025-11-05

### Changed - BREAKING CHANGES

**Major Architecture Migration: ETF/libnftnl → JSON/libnftables**

This release represents a complete rewrite of the underlying nftables communication layer, moving from manual netlink message construction to the official libnftables API.

#### Migration to JSON/libnftables API

- **Complete replacement of ETF/libnftnl backend** with official libnftables JSON API
- **Hybrid approach**: JSON for data operations (tables/chains/sets), nft syntax for rules
- **45% code reduction** (5000 → 2757 lines)
- **80% native code reduction** (2000+ → 400 lines)
- **Rule module simplified by 55%** (580 → 264 lines)

#### Breaking API Changes

1. **IP addresses now use string format instead of binaries**
   ```elixir
   # v0.3.0 (old)
   NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, [<<192, 168, 1, 100>>])

   # v0.4.0 (new)
   NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ["192.168.1.100"])
   ```

2. **Rules use nft syntax strings instead of expression builders**
   ```elixir
   # v0.3.0 (old)
   {:ok, payload_id} = Expr.payload_ipv4_saddr(pid, 1)
   {:ok, cmp_id} = Expr.cmp_eq(pid, 1, ip)

   # v0.4.0 (new)
   "ip saddr 192.168.1.100 drop"  # Simple nft syntax
   ```

3. **No resource ID management required**
   ```elixir
   # v0.3.0 (old)
   {:ok, table_id} <- Kernel.Table.alloc(pid)
   :ok <- Kernel.Table.set_str(pid, table_id, :name, name)
   :ok <- Kernel.Table.send_to_kernel(pid, table_id, :add)
   :ok <- Kernel.Table.free(pid, table_id)

   # v0.4.0 (new)
   NFTex.Table.create(pid, %{name: name, family: :inet})
   ```

### Added

- **NFTex.JSONPort** - GenServer wrapper for libnftables API (220 lines)
- **NFTex.JSONBuilder** - Builds JSON commands for tables/chains/sets (387 lines)
- **Hybrid architecture** - JSON for structured data, nft syntax for complex rules
- **Better error messages** - Directly from libnftables instead of custom parsing
- **Comprehensive test suite** - 182 tests with 100% pass rate

### Fixed

- **Set creation now works correctly** - Primary motivation for migration
- **More reliable operations** - Official API handles edge cases
- **Better nftables version compatibility** - No manual netlink message construction
- **Test suite** - All 182 tests passing (100% success rate)

### Removed - BREAKING CHANGES

- **NFTex.Port** - Replaced by NFTex.JSONPort
- **NFTex.ExpressionBuilder** - No longer needed (use nft syntax)
- **All NFTex.Kernel.*** modules** - No longer needed with JSON API

**Note:** High-level API (Table, Chain, Rule, Set, Policy, RuleBuilder) remains mostly compatible. Only low-level changes and IP format changes required.

### Performance

- Simpler codebase with less overhead
- Fewer allocations in native code
- Direct API calls instead of manual message construction

### Migration Guide

See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for detailed migration instructions from v0.3.0 to v0.4.0.

## [0.3.0] - 2025-11-05

### Added

#### High-Level Modules (Phase 3)

- **NFTex.Chain** - Complete chain management module
  - `create/2` - Create base chains (with hooks) or regular chains
  - `delete/4` - Delete chains
  - `list/2` - List all chains with filtering
  - `exists?/4` - Check if chain exists
  - `set_policy/5` - Set default policy for base chains
  - Comprehensive documentation with hook points, priorities, and chain types

- **NFTex.RuleBuilder** - Fluent API for building rules
  - Chainable interface for intuitive rule construction
  - Match functions: `match_source_ip/2`, `match_dest_ip/2`, `match_source_port/2`, `match_dest_port/2`, `match_ct_state/2`, `match_iif/2`, `match_oif/2`
  - Action functions: `counter/1`, `log/3`, `rate_limit/4`
  - Verdict functions: `accept/1`, `drop/1`, `reject/2`
  - `commit/1` - Execute all configured expressions
  - Automatic expression ordering and error handling

- **NFTex.Policy** - Pre-built firewall policies
  - `setup_basic_firewall/2` - Complete secure firewall in one call
  - `accept_loopback/2` - Accept loopback traffic
  - `accept_established/2` - Accept established/related connections
  - `drop_invalid/2` - Drop invalid packets
  - `allow_ssh/2` - Allow SSH with optional rate limiting and logging
  - `allow_http/2`, `allow_https/2`, `allow_dns/2` - Service-specific allows
  - Beginner-friendly with sensible defaults

#### Advanced Expressions (Phase 2)

- **Log Expression** - Comprehensive logging support
  - Kernel log integration (dmesg/journalctl)
  - Netlink logging (ulogd) for external tools
  - Configurable log levels (emerg, alert, crit, err, warning, notice, info, debug)
  - Custom prefixes and log groups
  - Snaplen and qthreshold configuration

- **Bitwise Expression** - Binary operations
  - Bitwise AND, OR, XOR operations
  - Left and right shift operations
  - Network masking and subnet matching
  - Port range extraction

- **Lookup Expression** - Set/map lookups
  - Fast set membership testing
  - Map value retrieval
  - Dynamic configuration support
  - IP blocklists and rate limit maps

- **FIB Expression** - Routing table queries
  - Reverse Path Filtering (RPF) for anti-spoofing
  - Output interface lookup
  - Address type detection
  - Route existence checks
  - Policy-based routing support

#### NAT Expressions (Phase 1)

- **SNAT/DNAT Support**
  - `nat_snat_ip/2` - Source NAT to specific IP
  - `nat_snat/3` - Source NAT with IP and port
  - `nat_dnat_ip/2` - Destination NAT to specific IP
  - `nat_dnat/3` - Destination NAT with IP and port
  - `nat_masquerade/1` - Dynamic SNAT (masquerading)
  - `nat_redirect/2` - Port redirection

#### Connection Tracking (Phase 1)

- **CT Expressions**
  - `ct_state/2` - Match connection tracking state (new, established, related, invalid)
  - `ct_direction/2` - Match packet direction (original, reply)
  - `ct_mark/2` - Match connection mark

#### Comprehensive Examples

Six production-ready example scripts demonstrating real-world firewall configurations:

1. **01_basic_firewall.exs** - Secure server baseline with DROP policy
2. **02_nat_gateway.exs** - Internet sharing, port forwarding, DMZ setup
3. **03_anti_spoofing.exs** - RPF, bogon filtering, martian packet detection
4. **04_rate_limiting.exs** - DDoS protection with rate limits
5. **05_advanced_logging.exs** - Kernel log, ulogd, traffic analysis
6. **06_load_balancing.exs** - Basic load balancing with DNAT

### Changed

- Enhanced `NFTex.Set.delete/3` to properly handle set deletion
- Improved documentation across all modules with detailed examples
- Updated examples README with comprehensive API reference
- Added module documentation (@moduledoc) to all new modules

### Technical Details

- Added FIB expression mappings to `native/src/commands/expr.zig`
- Implemented ~850 lines of new Elixir code across 3 major modules
- Created 6 comprehensive example scripts (~1800 lines)
- Enhanced existing modules with additional helper functions
- Zero breaking changes to existing APIs

### Documentation

- Complete @moduledoc and @doc annotations for all new functions
- Detailed examples for all expression types
- API quick reference in examples/README.md
- Comprehensive use cases and patterns
- Security best practices documented

### Dependencies

- No new external dependencies
- Uses existing `Bitwise` module for flag calculations
- Maintains zero-dependency architecture

## [0.2.0] - 2025-11-04

### Added

- Query operations module (NFTex.Query)
- Set management module (NFTex.Set)
- Rule operations module (NFTex.Rule)
- Expression builder helpers
- Batch operations support
- Table management (NFTex.Table)

### Security

- CAP_NET_ADMIN capability checks
- Secure port communication via ETF
- Resource cleanup and lifecycle management

## [0.1.0] - 2025-11-03

### Added

- Initial release
- Core NFTex.Port module for netlink communication
- Zig-based native port (libnf_ex)
- libnftnl bindings
- Basic table, chain, rule, and set operations
- ETF-based Erlang-Zig communication
- Resource management system

### Architecture

- Port-based architecture for fault isolation
- Direct libnftnl bindings (no shell commands)
- Automatic resource cleanup
- Type-safe Elixir interface

[Unreleased]: https://github.com/yourusername/nftex/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/yourusername/nftex/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/yourusername/nftex/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yourusername/nftex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/nftex/releases/tag/v0.1.0
