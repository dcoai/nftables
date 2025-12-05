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

  ## Import Options

  You have two ways to import expression building functions:

  ### Option 1: Use Macro (Import Everything)

  The simplest approach - automatically imports all expression modules:

      use NFTables

  This imports `NFTables.Expr` and all sub-modules, giving you access to all
  expression building functions. Best for interactive use or when you need
  many different types of expressions.

  ### Option 2: Selective Imports (Import What You Need)

  For production code, you may prefer explicit imports:

      import NFTables.Expr
      import NFTables.Expr.{Port, TCP, Verdicts}

  This gives you fine-grained control and makes dependencies explicit.
  Best for production code where you want to minimize namespace pollution.

  Both approaches are equally valid - choose based on your preferences and use case.

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

  @doc """
  Convenience macro to import all NFTables.Expr modules.

  When you `use NFTables`, all expression building modules are automatically imported,
  making all expression functions available without explicit imports.

  ## Example

      defmodule MyFirewall do
        use NFTables

        def build_rules(pid) do
          NFTables.add(table: "filter")
          |> NFTables.add(chain: "INPUT", type: :filter, hook: :input)
          |> NFTables.add(rule: tcp() |> dport(22) |> accept())
          |> NFTables.submit(pid: pid)
        end
      end

  This is equivalent to:

      import NFTables.Expr
      import NFTables.Expr.{IP, Port, TCP, Layer2, CT, Advanced, Actions, NAT, Verdicts, Meter, Protocols}

  ## Alternative: Selective Imports

  For production code, you may prefer explicit imports for clarity:

      import NFTables.Expr
      import NFTables.Expr.{Port, TCP, Verdicts}

  Both approaches are equally valid.
  """
  defmacro __using__(_opts) do
    # Get modules from generated index (NFTables.ExprIndex.all())
    # ExprIndex is generated at compile time by Mix.Tasks.Compile.ModuleIndexer
    expr_modules = NFTables.ExprIndex.all()

    # Build import statements
    imports =
      [quote(do: import(NFTables.Expr))] ++
        Enum.map(expr_modules, fn mod ->
          quote do: import(unquote(mod))
        end)

    quote do
      (unquote_splicing(imports))
    end
  end

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
  def add(opts), do: Builder.new(opts) |> add(opts)

  @doc """
  Contextual add operation (arity-2) - continues existing builder.

  ## Examples

      NFTables.add(table: "filter")
      |> NFTables.add(chain: "INPUT")
      |> NFTables.add(rule: [%{accept: nil}])
  """
  def add(%Builder{} = builder, opts), do: Builder.apply_with_opts(builder, :add, opts)

  @doc """
  delete/1 delete an object, starts a new builder.

  ## Examples

      builder |> delete(table: "filter")
      builder |> delete(chain: "input")
      builder |> delete(rule: [...], handle: 123)
  """
  def delete(opts), do: Builder.new() |> delete(opts)

  @doc """
  delete/2 operation same as delete/1 but continues existing builder.
  """
  def delete(%Builder{} = builder, opts), do: Builder.apply_with_opts(builder, :delete, opts)

  @doc """
  Contextual flush operation (arity-1) - starts new builder.
  """
  def flush(opts), do: Builder.new() |> flush(opts)

  @doc """
  Contextual flush operation (arity-2) - continues existing builder.

  options:
    :scope - when set to :all will flush everything (limited by :family option if that is specified)
    :family - limits flush to particular nft family: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  """
  def flush(%Builder{} = builder, opts) when is_list(opts) do
    # If specific object is provided (table, chain, etc), use regular flush
    # Otherwise default scope to :all for flush_ruleset
    has_object =
      Keyword.has_key?(opts, :table) or
        Keyword.has_key?(opts, :chain) or
        Keyword.has_key?(opts, :set) or
        Keyword.has_key?(opts, :map)

    case {Keyword.get(opts, :scope), has_object} do
      {:all, _} -> Builder.flush_ruleset(builder, opts)
      # Default to flush_ruleset when no object
      {nil, false} -> Builder.flush_ruleset(builder, opts)
      _ -> Builder.apply_with_opts(builder, :flush, opts)
    end
  end

  @doc """
  Contextual insert operation (arity-1) - starts new builder.

  Inserts a rule at a specific position in a chain.

  ## Examples

      import NFTables.Expr
      NFTables.insert(table: "filter", chain: "INPUT", rule: tcp() |> dport(22) |> accept(), index: 0)
  """
  def insert(opts), do: Builder.new() |> insert(opts)

  @doc """
  Contextual insert operation (arity-2) - continues existing builder.
  """
  def insert(%Builder{} = builder, opts), do: Builder.apply_with_opts(builder, :insert, opts)

  @doc """
  Contextual replace operation (arity-1) - starts new builder.

  Replaces a rule at a specific handle.

  ## Examples

      import NFTables.Expr
      NFTables.replace(table: "filter", chain: "INPUT", rule: tcp() |> dport(80) |> accept(), handle: 123)
  """
  def replace(opts), do: Builder.new() |> replace(opts)

  @doc """
  Contextual replace operation (arity-2) - continues existing builder.
  """
  def replace(%Builder{} = builder, opts), do: Builder.apply_with_opts(builder, :replace, opts)

  @doc """
  Contextual rename operation (arity-1) - starts new builder.

  Renames a chain.

  ## Examples

      NFTables.rename(table: "filter", chain: "input", newname: "INPUT")
  """
  def rename(opts), do: Builder.new() |> rename(opts)

  @doc """
  Contextual rename operation (arity-2) - continues existing builder.
  """
  def rename(%Builder{} = builder, opts), do: Builder.apply_with_opts(builder, :rename, opts)

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

  # Delegate other Builder functions for advanced use
  defdelegate to_json(builder), to: Builder
  defdelegate to_map(builder), to: Builder
  defdelegate set_family(builder, family), to: Builder
end
