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
  def add(opts) when is_list(opts) do
    Builder.new(opts)
    |> add(opts)
  end

  @doc """
  Contextual add operation (arity-2) - continues existing builder.

  ## Examples

      NFTablesEx.add(table: "filter")
      |> NFTablesEx.add(chain: "INPUT")
      |> NFTablesEx.add(rules: [rule() |> tcp() |> accept()])
  """
  def add(%Builder{} = builder, opts) when is_list(opts) do
    cond do
      # Multiple rules (bulk addition)
      Keyword.has_key?(opts, :rules) ->
        add_rule_set(builder, opts)

      # Single rule
      Keyword.has_key?(opts, :rule) ->
        add_rule(builder, opts)

      # Table + Chain together
      Keyword.has_key?(opts, :table) and Keyword.has_key?(opts, :chain) ->
        builder
        |> add_table_opts(opts)
        |> add_chain_opts(opts)

      # Just table
      Keyword.has_key?(opts, :table) ->
        add_table_opts(builder, opts)

      # Just chain
      Keyword.has_key?(opts, :chain) ->
        add_chain_opts(builder, opts)

      # Set
      Keyword.has_key?(opts, :set) ->
        add_set_opts(builder, opts)

      # Map
      Keyword.has_key?(opts, :map) ->
        add_map_opts(builder, opts)

      # Counter
      Keyword.has_key?(opts, :counter) ->
        add_counter_opts(builder, opts)

      true ->
        raise ArgumentError, """
        Invalid options for add/2. Expected one of:
        :table, :chain, :rule, :rules, :set, :map, :counter

        Got: #{inspect(opts)}
        """
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
    cond do
      Keyword.has_key?(opts, :table) -> delete_table_opts(builder, opts)
      Keyword.has_key?(opts, :chain) -> delete_chain_opts(builder, opts)
      Keyword.has_key?(opts, :rule) -> delete_rule_opts(builder, opts)
      Keyword.has_key?(opts, :set) -> delete_set_opts(builder, opts)
      true -> raise ArgumentError, "Invalid options for delete/2"
    end
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
      opts when is_list(opts) ->
        cond do
          Keyword.has_key?(opts, :table) -> flush_table_opts(builder, opts)
          Keyword.has_key?(opts, :chain) -> flush_chain_opts(builder, opts)
          Keyword.has_key?(opts, :set) -> flush_set_opts(builder, opts)
          true -> raise ArgumentError, "Invalid options for flush/2"
        end
    end
  end

  # Helper functions for bulk rule addition
  defp add_rule_set(%Builder{} = builder, opts) do
    rules_list = Keyword.fetch!(opts, :rules)
    table = Keyword.get(opts, :table, builder.current_table)
    chain = Keyword.get(opts, :chain, builder.current_chain)
    family = Keyword.get(opts, :family, builder.family)

    Enum.reduce(rules_list, builder, fn rule_spec, acc ->
      case rule_spec do
        %NFTablesEx.Match{expr_list: expr_list} ->
          Builder.add_rule(acc, expr_list, table: table, chain: chain, family: family)

        expr_list when is_list(expr_list) ->
          Builder.add_rule(acc, expr_list, table: table, chain: chain, family: family)
      end
    end)
  end

  defp add_rule(%Builder{} = builder, opts) do
    rule_spec = Keyword.fetch!(opts, :rule)
    table = Keyword.get(opts, :table, builder.current_table)
    chain = Keyword.get(opts, :chain, builder.current_chain)
    family = Keyword.get(opts, :family, builder.family)

    case rule_spec do
      %NFTablesEx.Match{expr_list: expr_list} ->
        Builder.add_rule(builder, expr_list, table: table, chain: chain, family: family)

      expr_list when is_list(expr_list) ->
        Builder.add_rule(builder, expr_list, table: table, chain: chain, family: family)
    end
  end

  defp add_table_opts(%Builder{} = builder, opts) do
    table_name = Keyword.fetch!(opts, :table)
    family = Keyword.get(opts, :family, builder.family)
    Builder.add_table(builder, table_name, family: family)
  end

  defp add_chain_opts(%Builder{} = builder, opts) do
    chain_name = Keyword.fetch!(opts, :chain)
    chain_opts = Keyword.drop(opts, [:chain])
    Builder.add_chain(builder, chain_name, chain_opts)
  end

  defp add_set_opts(%Builder{} = builder, opts) do
    set_name = Keyword.fetch!(opts, :set)
    set_opts = Keyword.drop(opts, [:set])
    Builder.add_set(builder, set_name, set_opts)
  end

  defp add_map_opts(%Builder{} = builder, opts) do
    map_name = Keyword.fetch!(opts, :map)
    map_opts = Keyword.drop(opts, [:map])
    Builder.add_map(builder, map_name, map_opts)
  end

  defp add_counter_opts(%Builder{} = builder, opts) do
    counter_name = Keyword.fetch!(opts, :counter)
    Builder.add_counter(builder, counter_name)
  end

  defp delete_table_opts(%Builder{} = builder, opts) do
    table_name = Keyword.fetch!(opts, :table)
    family = Keyword.get(opts, :family, builder.family)
    Builder.delete_table(builder, table_name, family: family)
  end

  defp delete_chain_opts(%Builder{} = builder, opts) do
    chain_name = Keyword.fetch!(opts, :chain)
    delete_opts = Keyword.drop(opts, [:chain])
    Builder.delete_chain(builder, chain_name, delete_opts)
  end

  defp delete_rule_opts(%Builder{} = builder, opts) do
    handle = Keyword.fetch!(opts, :rule)
    delete_opts = Keyword.drop(opts, [:rule])
    Builder.delete_rule(builder, Keyword.merge([handle: handle], delete_opts))
  end

  defp delete_set_opts(%Builder{} = builder, opts) do
    set_name = Keyword.fetch!(opts, :set)
    delete_opts = Keyword.drop(opts, [:set])
    Builder.delete_set(builder, set_name, delete_opts)
  end

  defp flush_table_opts(%Builder{} = builder, opts) do
    table_name = Keyword.fetch!(opts, :table)
    flush_opts = Keyword.drop(opts, [:table])
    Builder.flush_table(builder, table_name, flush_opts)
  end

  defp flush_chain_opts(%Builder{} = builder, opts) do
    chain_name = Keyword.fetch!(opts, :chain)
    flush_opts = Keyword.drop(opts, [:chain])
    Builder.flush_chain(builder, chain_name, flush_opts)
  end

  defp flush_set_opts(%Builder{} = builder, opts) do
    set_name = Keyword.fetch!(opts, :set)
    flush_opts = Keyword.drop(opts, [:set])
    Builder.flush_set(builder, set_name, flush_opts)
  end

  # Delegate other Builder functions for advanced use
  defdelegate to_json(builder), to: Builder
  defdelegate to_map(builder), to: Builder
  defdelegate set_family(builder, family), to: Builder
  defdelegate set_table(builder, table), to: Builder
  defdelegate set_chain(builder, chain), to: Builder

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
