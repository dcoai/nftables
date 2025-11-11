defmodule NFTablesEx do
  @moduledoc """
  Elixir interface to Linux nftables via libnftables JSON API.

  NFTablesEx provides a high-level, idiomatic Elixir API for managing nftables rules,
  using the official `libnftables` library with JSON for all communication.

  ## Quick Start

      {:ok, pid} = NFTablesEx.start_link()

      # Create a table
      NFTablesEx.Table.add(pid, %{name: "filter", family: :inet})

      # Create a chain
      NFTablesEx.Chain.add(pid, %{
        table: "filter",
        name: "input",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      })

      # Create a set for IP blocklist
      NFTablesEx.Set.add(pid, %{
        name: "blocklist",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr,
        elements: []
      })

      # Add IPs to the blocklist (string format)
      NFTablesEx.Set.add_elements(pid, "filter", "blocklist", :inet, [
        "192.168.1.100",
        "10.0.0.50"
      ])

      # Add a rule to drop blocklisted IPs
      NFTablesEx.Rule.add(pid, %{
        family: :inet,
        table: "filter",
        chain: "input",
        expr: "ip saddr @blocklist drop"
      })

  ## Module Organization

  ### High-Level APIs

  - `NFTablesEx.Table` - Table creation and management
  - `NFTablesEx.Chain` - Chain creation and management
  - `NFTablesEx.Set` - Set creation and element management
  - `NFTablesEx.Rule` - Rule creation with expression support
  - `NFTablesEx.Query` - Query tables, chains, rules, and sets

  ### Low-Level APIs

  - `NFTablesEx.Port` - JSON-based port communication (from NFTablesEx.Port package)
  - `NFTablesEx.Builder` - Fluent API for building nftables configurations

  ## Architecture

  NFTablesEx uses a port-based architecture for fault isolation and security:

  - The Zig port process runs with CAP_NET_ADMIN capability
  - Port binary: `priv/port_nftables` - JSON-only communication
  - All operations go through `libnftables` library (same as `nft` command)
  - No manual netlink message construction

  ## JSON API

  The underlying JSON format follows the official nftables JSON schema.
  See: https://wiki.nftables.org/wiki-nftables/index.php/JSON_API

  For advanced use cases, you can use `NFTablesEx.Builder` to construct custom
  firewall configurations with a fluent, functional interface.

  ## Migration from v0.3.x

  v0.4.0 introduces a complete rewrite using JSON instead of ETF/netlink:

  - **Removed**: All `NFTablesEx.Kernel.*` modules (no longer needed with JSON approach)
  - **Removed**: Resource ID-based API (libnftables handles resources internally)
  - **Changed**: High-level APIs simplified (no resource management)
  - **Added**: JSON-based port for simpler, more maintainable implementation

  The high-level API remains similar, but some details have changed. See the
  module documentation for each API (Table, Chain, Set, Rule) for details.
  """

  alias NFTablesEx.Port

  @type nft_family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev

  @doc """
  Starts the NFTablesEx port process.

  ## Options

    * `:name` - Register the process with a name (optional)
    * `:check_capabilities` - If `true`, checks CAP_NET_ADMIN on startup (default: `true`)

  ## Examples

      # Default behavior
      {:ok, pid} = NFTablesEx.start_link()

      # Skip capability check (not recommended for production)
      {:ok, pid} = NFTablesEx.start_link(check_capabilities: false)

      # With name registration
      {:ok, pid} = NFTablesEx.start_link(name: :nftables_ex)

  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    Port.start_link(opts)
  end

  @doc """
  Stops the NFTablesEx port process.

  All nftables objects remain in the kernel after stopping.
  Use `NFTablesEx.Query.flush_ruleset/2` to clean up if needed.

  ## Example

      NFTablesEx.stop(pid)

  """
  @spec stop(pid()) :: :ok
  def stop(pid) do
    GenServer.stop(pid)
  end
end
