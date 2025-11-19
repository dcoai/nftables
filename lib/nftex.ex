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

  # ============================================================================
  # Dual-Arity Builder API
  # ============================================================================

  alias NFTablesEx.Builder

  @type t :: Builder.t()

  @doc """
  Contextual add operation (arity-1) - starts new builder.

  Detects what to add based on keyword options provided.

  ## Examples

      # Add table
      NFTablesEx.add(table: "filter", family: :inet)

      # Add chain
      NFTablesEx.add(chain: "INPUT", type: :filter)

      # Add table and chain together
      NFTablesEx.add(table: "filter", chain: "INPUT", family: :inet)

      # Add multiple rules
      import NFTablesEx.Match
      NFTablesEx.add(rules: [
        rule() |> tcp() |> dport(22) |> accept(),
        rule() |> tcp() |> dport(80) |> accept()
      ])
  """
  def add(opts) when is_list(opts), do: Builder.new(opts) |> add(opts)

  
  @doc """
  Contextual add operation (arity-2) - continues existing builder.

  ## Examples

      NFTablesEx.add(table: "filter")
      |> NFTablesEx.add(chain: "INPUT")
      |> NFTablesEx.add(rule: [%{accept: nil}])
  """
  def add(%Builder{} = builder, opts) when is_list(opts) do
    # Handle :rules as batch operation
    if Keyword.has_key?(opts, :rules) do
      add_rule_set(builder, opts)
    else
      # Handle Match struct conversion for :rule
      opts = if Keyword.has_key?(opts, :rule) do
        rule_spec = Keyword.get(opts, :rule)
        case rule_spec do
          %NFTablesEx.Match{expr_list: expr_list} ->
            Keyword.put(opts, :rule, expr_list)
          _ ->
            opts
        end
      else
        opts
      end

      # Delegate to unified Builder API
      Builder.add(builder, opts)
    end
  end

  @doc """
  Contextual delete operation (arity-1) - starts new builder.
  """
  def delete(opts) when is_list(opts) do
    Builder.new()
    |> delete(opts)
  end

  @doc """
  Contextual delete operation (arity-2) - continues existing builder.
  """
  def delete(%Builder{} = builder, opts) when is_list(opts) do
    Builder.delete(builder, opts)
  end

  @doc """
  Contextual flush operation (arity-1) - starts new builder.
  """
  def flush(opts) when is_list(opts) or is_atom(opts) do
    Builder.new()
    |> flush(opts)
  end

  @doc """
  Contextual flush operation (arity-2) - continues existing builder.
  """
  def flush(%Builder{} = builder, opts) do
    case opts do
      :ruleset -> Builder.flush_ruleset(builder)
      :all -> Builder.flush(builder, [:all])
      opts when is_list(opts) -> Builder.flush(builder, opts)
    end
  end

  # Helper function for bulk rule addition
  defp add_rule_set(%Builder{} = builder, opts) do
    rules_list = Keyword.fetch!(opts, :rules)
    base_opts = Keyword.drop(opts, [:rules])

    Enum.reduce(rules_list, builder, fn rule_spec, acc ->
      rule_expr = case rule_spec do
        %NFTablesEx.Match{expr_list: expr_list} -> expr_list
        expr_list when is_list(expr_list) -> expr_list
      end

      Builder.add(acc, Keyword.put(base_opts, :rule, rule_expr))
    end)
  end

  # Delegate other Builder functions for advanced use
  defdelegate to_json(builder), to: Builder
  defdelegate to_map(builder), to: Builder
  defdelegate set_family(builder, family), to: Builder

  # ============================================================================
  # Policy & NAT Helpers (delegated)
  # ============================================================================

  defdelegate allow_ssh(pid, opts \\ []), to: NFTablesEx.Policy
  defdelegate allow_http(pid, opts \\ []), to: NFTablesEx.Policy
  defdelegate allow_https(pid, opts \\ []), to: NFTablesEx.Policy
  defdelegate accept_established(pid, opts \\ []), to: NFTablesEx.Policy
  defdelegate drop_invalid(pid, opts \\ []), to: NFTablesEx.Policy
  defdelegate setup_basic_firewall(pid, opts \\ []), to: NFTablesEx.Policy

  # NAT helpers - note: setup_masquerade requires (pid, interface, opts)
  # so we only delegate those that match the simple pattern
  # Users can call NFTablesEx.NAT.* directly for more complex functions
end
