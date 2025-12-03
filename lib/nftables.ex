defmodule NFTables do
  @moduledoc """
  Elixir interface to Linux nftables via libnftables JSON API.

  NFTables provides a high-level, idiomatic Elixir API for managing nftables rules,
  using the official `libnftables` library with JSON for all communication.

  ## Quick Start

  Start the NFTables port process and build firewall rules:

      # Start the port process
      {:ok, pid} = NFTables.Port.start_link()

      # Create a simple firewall
      import NFTables.Expr

      NFTables.add(table: "filter", family: :inet)
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input, priority: 0, policy: :drop)
      |> NFTables.add(rule: state([:established, :related]) |> accept())
      |> NFTables.add(rule: tcp() |> dport(22) |> accept())
      |> NFTables.submit(pid: pid)

      # Clean up when done
      NFTables.Port.stop(pid)

  ## Main API Functions

  ### Building Rules

  - `add/1-2` - Add tables, chains, rules, sets, etc.
  - `delete/1-2` - Delete objects
  - `flush/1-2` - Flush objects (remove contents)
  - `flush_ruleset/0-2` - Flush entire ruleset
  - `insert/1-2` - Insert rules at specific positions
  - `replace/1-2` - Replace rules at specific handles
  - `rename/1-2` - Rename chains

  ### Submitting Changes

  - `submit/1-2` - Submit configuration to nftables

  ### Helper Functions

  - `to_json/1` - Convert to JSON string
  - `to_map/1` - Convert to Elixir map
  - `set_family/2` - Set address family

  ## Module Organization

  ### Core APIs

  - `NFTables` - Main public API (this module)
  - `NFTables.Expr` - Fluent API for building rule expressions
  - `NFTables.Query` - Query tables, chains, rules, and sets

  ### Convenience APIs

  - `NFTables.Policy` - Pre-built security policies (accept_established, allow_ssh, etc.)
  - `NFTables.NAT` - NAT operations (port forwarding, masquerading, etc.)

  ### Execution & Port Management

  - `NFTables.Port` - Port process management (start_link, stop)
  - `NFTables.Local` - Local execution requestor

  ### Internal APIs

  - `NFTables.Builder` - Internal builder implementation (use NFTables API instead)
  - `NFTables.Decoder` - Decode nftables responses
  - `NFTables.Requestor` - Behaviour for custom submission handlers

  ## Pipeline Pattern

  All functions return a builder struct that can be piped:

      NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
      |> NFTables.add(rule: tcp() |> dport(80) |> accept())
      |> NFTables.add(rule: tcp() |> dport(443) |> accept())
      |> NFTables.submit(pid: pid)

  ## Context Tracking

  The builder automatically tracks context (table, chain) so you don't need to repeat it:

      NFTables.add(table: "filter", chain: "INPUT", type: :filter, hook: :input)
      |> NFTables.add(rule: tcp() |> dport(22) |> accept())
      |> NFTables.add(rule: tcp() |> dport(80) |> accept())
      # Both rules automatically use filter/INPUT

  ## Examples

  ### Basic Firewall

      import NFTables.Expr

      NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input, policy: :drop)
      |> NFTables.add(chain: "FORWARD", type: :filter, hook: :forward, policy: :drop)
      |> NFTables.add(chain: "OUTPUT", type: :filter, hook: :output, policy: :accept)
      |> NFTables.add(rule: iif("lo") |> accept())
      |> NFTables.add(rule: state([:established, :related]) |> accept())
      |> NFTables.add(rule: tcp() |> dport(22) |> accept())
      |> NFTables.submit(pid: pid)

  ### IP Blocking with Sets

      NFTables.add(table: "filter")
      |> NFTables.add(set: "blocklist", type: :ipv4_addr)
      |> NFTables.add(element: ["1.2.3.4", "5.6.7.8"], set: "blocklist")
      |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
      |> NFTables.add(rule: ip_saddr() |> set_lookup("@blocklist") |> drop())
      |> NFTables.submit(pid: pid)

  ### NAT / Port Forwarding

      NFTables.add(table: "nat", family: :ip)
      |> NFTables.add(chain: "PREROUTING", type: :nat, hook: :prerouting)
      |> NFTables.add(rule: tcp() |> dport(8080) |> dnat("192.168.1.100:80"))
      |> NFTables.submit(pid: pid)

  ## JSON API

  The underlying JSON format follows the official nftables JSON schema.
  See: https://wiki.nftables.org/wiki-nftables/index.php/JSON_API

  For advanced use cases requiring direct builder access, see `NFTables.Builder` documentation.
  """

  @type nft_family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev

  # ============================================================================
  # Main Public API
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
      import NFTables.Expr
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
          %NFTables.Expr{expr_list: expr_list} ->
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

  @doc """
  Contextual insert operation (arity-1) - starts new builder.

  Inserts a rule at a specific position in a chain.

  ## Examples

      import NFTables.Expr
      NFTables.insert(table: "filter", chain: "INPUT", rule: tcp() |> dport(22) |> accept(), index: 0)
  """
  def insert(opts) when is_list(opts) do
    Builder.new()
    |> insert(opts)
  end

  @doc """
  Contextual insert operation (arity-2) - continues existing builder.
  """
  def insert(%Builder{} = builder, opts) when is_list(opts) do
    Builder.insert(builder, opts)
  end

  @doc """
  Contextual replace operation (arity-1) - starts new builder.

  Replaces a rule at a specific handle.

  ## Examples

      import NFTables.Expr
      NFTables.replace(table: "filter", chain: "INPUT", rule: tcp() |> dport(80) |> accept(), handle: 123)
  """
  def replace(opts) when is_list(opts) do
    Builder.new()
    |> replace(opts)
  end

  @doc """
  Contextual replace operation (arity-2) - continues existing builder.
  """
  def replace(%Builder{} = builder, opts) when is_list(opts) do
    Builder.replace(builder, opts)
  end

  @doc """
  Contextual rename operation (arity-1) - starts new builder.

  Renames a chain.

  ## Examples

      NFTables.rename(table: "filter", chain: "input", newname: "INPUT")
  """
  def rename(opts) when is_list(opts) do
    Builder.new()
    |> rename(opts)
  end

  @doc """
  Contextual rename operation (arity-2) - continues existing builder.
  """
  def rename(%Builder{} = builder, opts) when is_list(opts) do
    Builder.rename(builder, opts)
  end

  @doc """
  Submit the builder configuration using the configured requestor.

  Uses the requestor module specified in the builder's `requestor` field
  (defaults to `NFTables.Local` for local execution).

  ## Examples

      {:ok, pid} = NFTables.Port.start_link()

      NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> NFTables.submit(pid: pid)
  """
  @spec submit(Builder.t()) :: :ok | {:ok, term()} | {:error, term()}
  def submit(%Builder{} = builder) do
    Builder.submit(builder)
  end

  @doc """
  Submit the builder configuration with options or override requestor.

  ## Examples

      NFTables.add(table: "filter")
      |> NFTables.submit(pid: pid, timeout: 10_000)

      # Override requestor
      NFTables.add(table: "filter")
      |> NFTables.submit(requestor: MyApp.RemoteRequestor, node: :remote)
  """
  @spec submit(Builder.t(), keyword()) :: :ok | {:ok, term()} | {:error, term()}
  def submit(%Builder{} = builder, opts) when is_list(opts) do
    Builder.submit(builder, opts)
  end

  @doc """
  Flush the entire ruleset (remove all tables, chains, and rules).

  ## Options

  - `:family` - Optional family to flush (default: all families)

  ## Examples

      # Flush all tables/chains/rules for all families
      NFTables.flush_ruleset()
      |> NFTables.submit(pid: pid)

      # Flush only inet family
      NFTables.flush_ruleset(family: :inet)
      |> NFTables.submit(pid: pid)
  """
  @spec flush_ruleset(keyword()) :: Builder.t()
  def flush_ruleset(opts \\ []) do
    Builder.new()
    |> Builder.flush_ruleset(opts)
  end

  @doc """
  Flush the entire ruleset (arity-2) - continues existing builder.
  """
  @spec flush_ruleset(Builder.t(), keyword()) :: Builder.t()
  def flush_ruleset(%Builder{} = builder, opts) when is_list(opts) do
    Builder.flush_ruleset(builder, opts)
  end

  # Helper function for bulk rule addition
  defp add_rule_set(%Builder{} = builder, opts) do
    rules_list = Keyword.fetch!(opts, :rules)
    base_opts = Keyword.drop(opts, [:rules])

    Enum.reduce(rules_list, builder, fn rule_spec, acc ->
      rule_expr = case rule_spec do
        %NFTables.Expr{expr_list: expr_list} -> expr_list
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
