defmodule NFTables do
  @moduledoc """
  Elixir interface to Linux nftables via libnftables JSON API.

  NFTables provides a high-level, idiomatic Elixir API for managing nftables rules,
  using the official `libnftables` library with JSON for all communication.

  ## Quick Start

      {:ok, pid} = NFTables.start_link()

      # Create table, chain, and set using Builder
      alias NFTables.Builder

      Builder.new()
      |> Builder.add(table: "filter", family: :inet)
      |> Builder.add(
        table: "filter",
        chain: "input",
        family: :inet,
        type: :filter,
        hook: :input,
        priority: 0,
        policy: :accept
      )
      |> Builder.add(
        set: "blocklist",
        table: "filter",
        family: :inet,
        type: :ipv4_addr
      )
      |> Builder.add(
        element: ["192.168.1.100", "10.0.0.50"],
        set: "blocklist",
        table: "filter",
        family: :inet
      )
      |> Builder.execute(pid)

      # Or use high-level convenience APIs
      import NFTables.Match

      block_rule = rule()
      |> source_ip_set("@blocklist")
      |> drop()

      Builder.new()
      |> Builder.add(rule: block_rule, table: "filter", chain: "input")
      |> Builder.execute(pid)

  ## Module Organization

  ### Core APIs

  - `NFTables.Builder` - Unified API for building nftables configurations (tables, chains, sets, rules)
  - `NFTables.Match` - Fluent API for building rule expressions
  - `NFTables.Query` - Query tables, chains, rules, and sets

  ### Convenience APIs

  - `NFTables.Policy` - Pre-built security policies (accept_established, allow_ssh, etc.)
  - `NFTables.NAT` - NAT operations (port forwarding, masquerading, etc.)

  ### Low-Level APIs

  - `NFTables.Port` - JSON-based port communication (from NFTables.Port package)
  - `NFTables.Executor` - Execute nftables commands
  - `NFTables.Decoder` - Decode nftables responses

  ## Architecture

  NFTables uses a port-based architecture for fault isolation and security:

  - The Zig port process runs with CAP_NET_ADMIN capability
  - Port binary: `priv/port_nftables` - JSON-only communication
  - All operations go through `libnftables` library (same as `nft` command)
  - No manual netlink message construction

  ## JSON API

  The underlying JSON format follows the official nftables JSON schema.
  See: https://wiki.nftables.org/wiki-nftables/index.php/JSON_API

  For advanced use cases, you can use `NFTables.Builder` to construct custom
  firewall configurations with a fluent, functional interface.

  ## Migration from v0.3.x

  v0.4.0 introduces a complete rewrite using JSON instead of ETF/netlink:

  - **Removed**: All `NFTables.Kernel.*` modules (no longer needed with JSON approach)
  - **Removed**: Resource ID-based API (libnftables handles resources internally)
  - **Removed**: `NFTables.Table`, `NFTables.Chain`, `NFTables.Set` (replaced by unified `NFTables.Builder` API)
  - **Changed**: High-level APIs simplified (no resource management)
  - **Added**: JSON-based port for simpler, more maintainable implementation
  - **Added**: Unified `Builder` API for all nftables objects

  See the `NFTables.Builder` documentation for the new unified API.
  """

  alias NFTables.Port

  @type nft_family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev

  @doc """
  Starts the NFTables port process.

  ## Options

    * `:name` - Register the process with a name (optional)
    * `:check_capabilities` - If `true`, checks CAP_NET_ADMIN on startup (default: `true`)

  ## Examples

      # Default behavior
      {:ok, pid} = NFTables.start_link()

      # Skip capability check (not recommended for production)
      {:ok, pid} = NFTables.start_link(check_capabilities: false)

      # With name registration
      {:ok, pid} = NFTables.start_link(name: :nftables_ex)

  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    Port.start_link(opts)
  end

  @doc """
  Stops the NFTables port process.

  All nftables objects remain in the kernel after stopping.
  Use `NFTables.Query.flush_ruleset/2` to clean up if needed.

  ## Example

      NFTables.stop(pid)

  """
  @spec stop(pid()) :: :ok
  def stop(pid) do
    GenServer.stop(pid)
  end

  # ============================================================================
  # Dual-Arity Builder API
  # ============================================================================

  alias NFTables.Builder

  @type t :: Builder.t()

  @doc """
  Contextual add operation (arity-1) - starts new builder.

  Detects what to add based on keyword options provided.

  ## Examples

      # Add table
      NFTables.add(table: "filter", family: :inet)

      # Add chain
      NFTables.add(chain: "INPUT", type: :filter)

      # Add table and chain together
      NFTables.add(table: "filter", chain: "INPUT", family: :inet)

      # Add multiple rules
      import NFTables.Match
      NFTables.add(rules: [
        rule() |> tcp() |> dport(22) |> accept(),
        rule() |> tcp() |> dport(80) |> accept()
      ])
  """
  def add(opts) when is_list(opts), do: Builder.new(opts) |> add(opts)

  
  @doc """
  Contextual add operation (arity-2) - continues existing builder.

  ## Examples

      NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> NFTables.add(rule: [%{accept: nil}])
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
          %NFTables.Match{expr_list: expr_list} ->
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
        %NFTables.Match{expr_list: expr_list} -> expr_list
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

  defdelegate allow_ssh(pid, opts \\ []), to: NFTables.Policy
  defdelegate allow_http(pid, opts \\ []), to: NFTables.Policy
  defdelegate allow_https(pid, opts \\ []), to: NFTables.Policy
  defdelegate accept_established(pid, opts \\ []), to: NFTables.Policy
  defdelegate drop_invalid(pid, opts \\ []), to: NFTables.Policy
  defdelegate setup_basic_firewall(pid, opts \\ []), to: NFTables.Policy

  # NAT helpers - note: setup_masquerade requires (pid, interface, opts)
  # so we only delegate those that match the simple pattern
  # Users can call NFTables.NAT.* directly for more complex functions
end
