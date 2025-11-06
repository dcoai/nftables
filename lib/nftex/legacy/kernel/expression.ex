defmodule NFTex.Kernel.Expression do
  @moduledoc """
  Low-level expression operations - direct libnftnl bindings.

  Expressions are the building blocks of nftables rules. They perform matching,
  actions, and verdicts on packets.

  ## Expression Types

  nftables supports 30+ expression types including:
  - `"counter"` - Count packets/bytes
  - `"payload"` - Match packet header data
  - `"cmp"` - Comparison operations
  - `"immediate"` - Load immediate values (verdicts)
  - `"nat"` - Network address translation
  - `"limit"` - Rate limiting
  - `"log"` - Packet logging
  - `"ct"` - Connection tracking
  - And many more...

  ## Attribute Setting

  Each expression type has its own set of attributes. Use the generic
  `set_u8/4`, `set_u16/4`, `set_u32/4`, `set_u64/4`, `set_str/4`, and
  `set_data/4` functions to configure expression-specific attributes.

  See NFTABLES_MODULES.md for documentation of all expression types
  and their attributes.

  ## Example

      # Create counter expression (no attributes)
      {:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "counter")

      # Create payload expression (match IP source)
      {:ok, expr_id} = NFTex.Kernel.Expression.alloc(pid, "payload")
      :ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :base, 1)      # NETWORK
      :ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :offset, 12)   # IP src
      :ok = NFTex.Kernel.Expression.set_u32(pid, expr_id, :len, 4)
      :ok = NFTex.Kernel.Expression.set_u8(pid, expr_id, :dreg, 1)

      # Add to rule
      :ok = NFTex.Kernel.Rule.add_expr(pid, rule_id, expr_id)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc """
  Allocates a new expression of the specified type.

  ## Expression Types

  Common types: "counter", "payload", "cmp", "immediate", "nat", "limit",
  "log", "ct", "meta", "lookup", "quota", "reject", "queue", etc.

  See `/usr/include/libnftnl/expr.h` for complete list.
  """
  @spec alloc(pid(), String.t()) :: {:ok, resource_id()} | {:error, term()}
  def alloc(pid, expr_name) do
    Port.call(pid, {:expr_alloc, expr_name})
  end

  @doc "Frees an expression resource."
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id), do: Port.call(pid, {:expr_free, resource_id})

  @doc "Sets a u8 attribute on an expression."
  @spec set_u8(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u8(pid, resource_id, attr, value) do
    Port.call(pid, {:expr_set_u8, resource_id, attr, value})
  end

  @doc "Sets a u16 attribute on an expression."
  @spec set_u16(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u16(pid, resource_id, attr, value) do
    Port.call(pid, {:expr_set_u16, resource_id, attr, value})
  end

  @doc "Sets a u32 attribute on an expression."
  @spec set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u32(pid, resource_id, attr, value) do
    Port.call(pid, {:expr_set_u32, resource_id, attr, value})
  end

  @doc "Sets a u64 attribute on an expression."
  @spec set_u64(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u64(pid, resource_id, attr, value) do
    Port.call(pid, {:expr_set_u64, resource_id, attr, value})
  end

  @doc "Sets a string attribute on an expression."
  @spec set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def set_str(pid, resource_id, attr, value) do
    Port.call(pid, {:expr_set_str, resource_id, attr, value})
  end

  @doc """
  Sets binary data on an expression.

  Used for attributes that require raw binary data, such as IP addresses,
  comparison data, etc.
  """
  @spec set_data(pid(), resource_id(), atom(), binary()) :: :ok | {:error, term()}
  def set_data(pid, resource_id, attr, data) do
    Port.call(pid, {:expr_set_data, resource_id, attr, data})
  end
end
