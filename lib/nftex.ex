defmodule NFTex do
  @moduledoc """
  Elixir interface to Linux nftables via libnftnl library.

  NFTex provides a modular interface to nftables with both high-level
  idiomatic Elixir APIs and low-level kernel bindings.

  ## Quick Start

      {:ok, pid} = NFTex.start_link()

      # High-level API (recommended)
      NFTex.Table.create(pid, %{name: "filter", family: :inet})
      NFTex.Chain.create(pid, %{
        table: "filter", name: "input", family: :inet,
        type: :filter, hook: :input, priority: 0, policy: :accept
      })

      # Low-level Kernel API (for advanced use)
      {:ok, table_id} = NFTex.Kernel.Table.alloc(pid)
      :ok = NFTex.Kernel.Table.set_str(pid, table_id, :name, "filter")
      :ok = NFTex.Kernel.Table.free(pid, table_id)

  ## Module Organization

  ### High-Level APIs

  Use these for most operations - they provide automatic resource management
  and idiomatic Elixir interfaces:

  - `NFTex.Query` - Query tables, chains, rules, sets, and elements
  - `NFTex.Set` - Set creation and element management
  - `NFTex.Rule` - Rule creation with simple helpers (block_ip, accept_ip)
  - `NFTex.ExpressionBuilder` - Build nftables expressions
  - `NFTex.Table` - Table operations
  - `NFTex.Chain` - Chain operations

  ### Low-Level Kernel APIs

  Use these when you need fine-grained control or for features not yet
  available in high-level APIs:

  - `NFTex.Kernel.Table` - Direct table bindings
  - `NFTex.Kernel.Chain` - Direct chain bindings
  - `NFTex.Kernel.Rule` - Direct rule bindings
  - `NFTex.Kernel.Expression` - Expression operations
  - `NFTex.Kernel.Set` - Direct set bindings
  - `NFTex.Kernel.SetElement` - Set element operations
  - `NFTex.Kernel.Batch` - Batch operations
  - `NFTex.Kernel.Netlink` - Netlink socket and communication operations

  ### Documentation

  See `NFTABLES_MODULES.md` for comprehensive documentation of all nftables
  features, implementation status, and examples.

  ## Architecture

  NFTex uses a port-based architecture for fault isolation and security:
  - The Zig port process runs with CAP_NET_ADMIN capability
  - Communication uses Erlang External Term Format (ETF)
  - Resources are tracked by opaque resource IDs
  - High-level APIs handle resource management automatically

  ## Legacy API (Deprecated)

  The old flat API (e.g., `NFTex.table_alloc/1`) is still available for
  backward compatibility but is deprecated. Use the new modular APIs instead:

  - Old: `NFTex.table_alloc(pid)` → New: `NFTex.Kernel.Table.alloc(pid)`
  - Old: `NFTex.table_set_str(...)` → New: `NFTex.Kernel.Table.set_str(...)`

  All old functions delegate to the new `NFTex.Kernel.*` modules.
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()
  @type nft_family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev

  # Entry Point

  @doc """
  Starts the NFTex port process.

  ## Options

    * `:name` - Register the process with a name (optional)
    * `:check_capabilities` - If `true`, fails to start if CAP_NET_ADMIN is not set (optional, default: `true`)

  ## Example

      # Default behavior - requires capabilities
      {:ok, pid} = NFTex.start_link()
      # Returns: {:error, "capability cap_net_admin not set"} if not set

      # Skip capability check (not recommended for production)
      {:ok, pid} = NFTex.start_link(check_capabilities: false)

      # With name registration
      {:ok, pid} = NFTex.start_link(name: :nftex)

  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    Port.start_link(opts)
  end

  @doc """
  Stops the NFTex port process.

  All resources will be cleaned up automatically.

  ## Example

      NFTex.stop(pid)

  """
  @spec stop(pid()) :: :ok
  def stop(pid) do
    Port.stop(pid)
  end

  @doc """
  Check if the port process has the required CAP_NET_ADMIN capability.

  Returns `true` if CAP_NET_ADMIN is available, `false` otherwise.

  ## Example

      {:ok, pid} = NFTex.start_link()
      if NFTex.has_capabilities?(pid) do
        # Netlink operations will work
        NFTex.Table.create(pid, %{name: "test", family: :ip})
      else
        # Need to set capability with: sudo setcap cap_net_admin=ep path/to/libnf_ex
        Logger.warning("CAP_NET_ADMIN not available")
      end

  """
  @spec has_capabilities?(pid()) :: boolean()
  def has_capabilities?(pid) do
    Port.has_capabilities?(pid)
  end

  #
  # Legacy API - Deprecated
  #
  # The functions below are kept for backward compatibility.
  # New code should use NFTex.Kernel.* modules directly.
  #

  # Table operations (deprecated - use NFTex.Kernel.Table)

  @deprecated "Use NFTex.Kernel.Table.alloc/1 instead"
  @spec table_alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def table_alloc(pid), do: NFTex.Kernel.Table.alloc(pid)

  @deprecated "Use NFTex.Kernel.Table.free/2 instead"
  @spec table_free(pid(), resource_id()) :: :ok | {:error, term()}
  def table_free(pid, resource_id), do: NFTex.Kernel.Table.free(pid, resource_id)

  @deprecated "Use NFTex.Kernel.Table.set_str/4 instead"
  @spec table_set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def table_set_str(pid, resource_id, attr, value) do
    NFTex.Kernel.Table.set_str(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Table.set_u32/4 instead"
  @spec table_set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def table_set_u32(pid, resource_id, attr, value) do
    NFTex.Kernel.Table.set_u32(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Table.get_str/3 instead"
  @spec table_get_str(pid(), resource_id(), atom()) :: {:ok, String.t()} | {:error, term()}
  def table_get_str(pid, resource_id, attr) do
    NFTex.Kernel.Table.get_str(pid, resource_id, attr)
  end

  @deprecated "Use NFTex.Kernel.Table.get_u32/3 instead"
  @spec table_get_u32(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def table_get_u32(pid, resource_id, attr) do
    NFTex.Kernel.Table.get_u32(pid, resource_id, attr)
  end

  # Chain operations (deprecated - use NFTex.Kernel.Chain)

  @deprecated "Use NFTex.Kernel.Chain.alloc/1 instead"
  @spec chain_alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def chain_alloc(pid), do: NFTex.Kernel.Chain.alloc(pid)

  @deprecated "Use NFTex.Kernel.Chain.free/2 instead"
  @spec chain_free(pid(), resource_id()) :: :ok | {:error, term()}
  def chain_free(pid, resource_id), do: NFTex.Kernel.Chain.free(pid, resource_id)

  @deprecated "Use NFTex.Kernel.Chain.set_str/4 instead"
  @spec chain_set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def chain_set_str(pid, resource_id, attr, value) do
    NFTex.Kernel.Chain.set_str(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Chain.set_u32/4 instead"
  @spec chain_set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def chain_set_u32(pid, resource_id, attr, value) do
    NFTex.Kernel.Chain.set_u32(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Chain.set_u8/4 instead"
  @spec chain_set_u8(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def chain_set_u8(pid, resource_id, attr, value) do
    NFTex.Kernel.Chain.set_u8(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Chain.get_str/3 instead"
  @spec chain_get_str(pid(), resource_id(), atom()) :: {:ok, String.t()} | {:error, term()}
  def chain_get_str(pid, resource_id, attr) do
    NFTex.Kernel.Chain.get_str(pid, resource_id, attr)
  end

  @deprecated "Use NFTex.Kernel.Chain.get_u32/3 instead"
  @spec chain_get_u32(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def chain_get_u32(pid, resource_id, attr) do
    NFTex.Kernel.Chain.get_u32(pid, resource_id, attr)
  end

  # Rule operations (deprecated - use NFTex.Kernel.Rule)

  @deprecated "Use NFTex.Kernel.Rule.alloc/1 instead"
  @spec rule_alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def rule_alloc(pid), do: NFTex.Kernel.Rule.alloc(pid)

  @deprecated "Use NFTex.Kernel.Rule.free/2 instead"
  @spec rule_free(pid(), resource_id()) :: :ok | {:error, term()}
  def rule_free(pid, resource_id), do: NFTex.Kernel.Rule.free(pid, resource_id)

  @deprecated "Use NFTex.Kernel.Rule.set_str/4 instead"
  @spec rule_set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def rule_set_str(pid, resource_id, attr, value) do
    NFTex.Kernel.Rule.set_str(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Rule.set_u32/4 instead"
  @spec rule_set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def rule_set_u32(pid, resource_id, attr, value) do
    NFTex.Kernel.Rule.set_u32(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Rule.set_u64/4 instead"
  @spec rule_set_u64(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def rule_set_u64(pid, resource_id, attr, value) do
    NFTex.Kernel.Rule.set_u64(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Rule.add_expr/3 instead"
  @spec rule_add_expr(pid(), resource_id(), resource_id()) :: :ok | {:error, term()}
  def rule_add_expr(pid, rule_id, expr_id) do
    NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
  end

  @deprecated "Use NFTex.Kernel.Rule.get_str/3 instead"
  @spec rule_get_str(pid(), resource_id(), atom()) :: {:ok, String.t()} | {:error, term()}
  def rule_get_str(pid, resource_id, attr) do
    NFTex.Kernel.Rule.get_str(pid, resource_id, attr)
  end

  @deprecated "Use NFTex.Kernel.Rule.get_u32/3 instead"
  @spec rule_get_u32(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def rule_get_u32(pid, resource_id, attr) do
    NFTex.Kernel.Rule.get_u32(pid, resource_id, attr)
  end

  @deprecated "Use NFTex.Kernel.Rule.get_u64/3 instead"
  @spec rule_get_u64(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def rule_get_u64(pid, resource_id, attr) do
    NFTex.Kernel.Rule.get_u64(pid, resource_id, attr)
  end

  # Expression operations (deprecated - use NFTex.Kernel.Expression)

  @deprecated "Use NFTex.Kernel.Expression.alloc/2 instead"
  @spec expr_alloc(pid(), String.t()) :: {:ok, resource_id()} | {:error, term()}
  def expr_alloc(pid, name), do: NFTex.Kernel.Expression.alloc(pid, name)

  @deprecated "Use NFTex.Kernel.Expression.free/2 instead"
  @spec expr_free(pid(), resource_id()) :: :ok | {:error, term()}
  def expr_free(pid, resource_id), do: NFTex.Kernel.Expression.free(pid, resource_id)

  @deprecated "Use NFTex.Kernel.Expression.set_u8/4 instead"
  @spec expr_set_u8(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def expr_set_u8(pid, resource_id, attr, value) do
    NFTex.Kernel.Expression.set_u8(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Expression.set_u16/4 instead"
  @spec expr_set_u16(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def expr_set_u16(pid, resource_id, attr, value) do
    NFTex.Kernel.Expression.set_u16(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Expression.set_u32/4 instead"
  @spec expr_set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def expr_set_u32(pid, resource_id, attr, value) do
    NFTex.Kernel.Expression.set_u32(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Expression.set_u64/4 instead"
  @spec expr_set_u64(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def expr_set_u64(pid, resource_id, attr, value) do
    NFTex.Kernel.Expression.set_u64(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Expression.set_str/4 instead"
  @spec expr_set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def expr_set_str(pid, resource_id, attr, value) do
    NFTex.Kernel.Expression.set_str(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Expression.set_data/4 instead"
  @spec expr_set_data(pid(), resource_id(), atom(), binary()) :: :ok | {:error, term()}
  def expr_set_data(pid, resource_id, attr, data) do
    NFTex.Kernel.Expression.set_data(pid, resource_id, attr, data)
  end

  # Set operations (deprecated - use NFTex.Kernel.Set)

  @deprecated "Use NFTex.Kernel.Set.alloc/1 instead"
  @spec set_alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def set_alloc(pid), do: NFTex.Kernel.Set.alloc(pid)

  @deprecated "Use NFTex.Kernel.Set.free/2 instead"
  @spec set_free(pid(), resource_id()) :: :ok | {:error, term()}
  def set_free(pid, resource_id), do: NFTex.Kernel.Set.free(pid, resource_id)

  @deprecated "Use NFTex.Kernel.Set.set_str/4 instead"
  @spec set_set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def set_set_str(pid, resource_id, attr, value) do
    NFTex.Kernel.Set.set_str(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.Set.set_u32/4 instead"
  @spec set_set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_set_u32(pid, resource_id, attr, value) do
    NFTex.Kernel.Set.set_u32(pid, resource_id, attr, value)
  end

  # Set element operations (deprecated - use NFTex.Kernel.SetElement)

  @deprecated "Use NFTex.Kernel.SetElement.alloc/1 instead"
  @spec set_elem_alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def set_elem_alloc(pid), do: NFTex.Kernel.SetElement.alloc(pid)

  @deprecated "Use NFTex.Kernel.SetElement.free/2 instead"
  @spec set_elem_free(pid(), resource_id()) :: :ok | {:error, term()}
  def set_elem_free(pid, resource_id), do: NFTex.Kernel.SetElement.free(pid, resource_id)

  @deprecated "Use NFTex.Kernel.SetElement.set_data/4 instead"
  @spec set_elem_set_data(pid(), resource_id(), atom(), binary()) :: :ok | {:error, term()}
  def set_elem_set_data(pid, resource_id, attr, data) do
    NFTex.Kernel.SetElement.set_data(pid, resource_id, attr, data)
  end

  @deprecated "Use NFTex.Kernel.SetElement.set_u32/4 instead"
  @spec set_elem_set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_elem_set_u32(pid, resource_id, attr, value) do
    NFTex.Kernel.SetElement.set_u32(pid, resource_id, attr, value)
  end

  @deprecated "Use NFTex.Kernel.SetElement.add/3 instead"
  @spec set_elem_add(pid(), resource_id(), resource_id()) :: :ok | {:error, term()}
  def set_elem_add(pid, set_id, elem_id) do
    NFTex.Kernel.SetElement.add(pid, set_id, elem_id)
  end

  # Batch operations (deprecated - use NFTex.Kernel.Batch)

  @deprecated "Use NFTex.Kernel.Batch.alloc/3 instead"
  @spec batch_alloc(pid(), non_neg_integer(), non_neg_integer()) ::
          {:ok, resource_id()} | {:error, term()}
  def batch_alloc(pid, page_size \\ 4096, max_pages \\ 20) do
    NFTex.Kernel.Batch.alloc(pid, page_size, max_pages)
  end

  @deprecated "Use NFTex.Kernel.Batch.free/2 instead"
  @spec batch_free(pid(), resource_id()) :: :ok | {:error, term()}
  def batch_free(pid, resource_id), do: NFTex.Kernel.Batch.free(pid, resource_id)
end
