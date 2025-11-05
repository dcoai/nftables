defmodule NFTex.Kernel.Chain do
  @moduledoc """
  Low-level chain operations - direct libnftnl bindings.

  This module provides direct access to the underlying nftables chain API
  with manual resource management. For most use cases, prefer `NFTex.Chain`.

  ## Resource Management

  Resources allocated with `alloc/1` must be explicitly freed with `free/2`.

  ## Example

      {:ok, chain_id} = NFTex.Kernel.Chain.alloc(pid)
      :ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :name, "input")
      :ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :table, "filter")
      :ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :family, 2)
      # ... configure more attributes ...
      :ok = NFTex.Kernel.Chain.free(pid, chain_id)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc "Allocates a new chain resource."
  @spec alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def alloc(pid), do: Port.call(pid, {:chain_alloc})

  @doc "Frees a chain resource."
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id), do: Port.call(pid, {:chain_free, resource_id})

  @doc """
  Sets a string attribute on a chain.

  Supported attributes: `:name`, `:table`, `:type`, `:dev`
  """
  @spec set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def set_str(pid, resource_id, attr, value) do
    Port.call(pid, {:chain_set_str, resource_id, attr, value})
  end

  @doc """
  Sets a u32 attribute on a chain.

  Supported attributes: `:family`, `:hooknum`, `:prio`, `:policy`, `:use`
  """
  @spec set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u32(pid, resource_id, attr, value) do
    Port.call(pid, {:chain_set_u32, resource_id, attr, value})
  end

  @doc """
  Sets a u8 attribute on a chain.

  Currently no u8 attributes are supported - policy should use set_u32.
  This function is reserved for future u8 attributes.
  """
  @spec set_u8(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u8(pid, resource_id, attr, value) do
    Port.call(pid, {:chain_set_u8, resource_id, attr, value})
  end

  @doc "Gets a string attribute from a chain."
  @spec get_str(pid(), resource_id(), atom()) :: {:ok, String.t()} | {:error, term()}
  def get_str(pid, resource_id, attr) do
    Port.call(pid, {:chain_get_str, resource_id, attr})
  end

  @doc "Gets a u32 attribute from a chain."
  @spec get_u32(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def get_u32(pid, resource_id, attr) do
    Port.call(pid, {:chain_get_u32, resource_id, attr})
  end

  @doc """
  Sends a chain to the kernel via netlink.

  This function communicates with the kernel's nftables subsystem via netlink
  to add or delete a chain. Requires `CAP_NET_ADMIN` capability.

  ## Arguments

  - `pid` - The NFTex port process
  - `resource_id` - The chain resource ID (from `alloc/1`)
  - `cmd` - The command to perform:
    - `:add` - Create the chain in the kernel
    - `:delete` - Remove the chain from the kernel

  ## Returns

  - `:ok` - Operation succeeded
  - `{:error, reason}` - Operation failed

  ## Example

      # Create chain
      {:ok, chain_id} = NFTex.Kernel.Chain.alloc(pid)
      :ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :table, "filter")
      :ok = NFTex.Kernel.Chain.set_str(pid, chain_id, :name, "input")
      :ok = NFTex.Kernel.Chain.set_u32(pid, chain_id, :family, 2)
      :ok = NFTex.Kernel.Chain.send_to_kernel(pid, chain_id, :add)

      # Delete chain
      :ok = NFTex.Kernel.Chain.send_to_kernel(pid, chain_id, :delete)
      :ok = NFTex.Kernel.Chain.free(pid, chain_id)

  ## Errors

  Common error reasons include:

  - `"Permission denied (EACCES)"` - Missing CAP_NET_ADMIN capability
  - `"File exists (EEXIST)"` - Chain already exists (when using `:add`)
  - `"No such file or directory (ENOENT)"` - Chain doesn't exist (when using `:delete`)

  """
  @spec send_to_kernel(pid(), resource_id(), :add | :delete) :: :ok | {:error, term()}
  def send_to_kernel(pid, resource_id, cmd) when cmd in [:add, :delete] do
    Port.call(pid, {:chain_send_to_kernel, resource_id, cmd})
  end
end
