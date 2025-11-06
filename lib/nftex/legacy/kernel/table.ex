defmodule NFTex.Kernel.Table do
  @moduledoc """
  Low-level table operations - direct libnftnl bindings.

  This module provides direct access to the underlying nftables table API
  with manual resource management. For most use cases, prefer `NFTex.Table`
  which provides automatic resource management and a more idiomatic interface.

  ## When to use this module

  - When you need fine-grained control over resource lifecycle
  - When building custom high-level abstractions
  - When implementing advanced nftables features not yet in high-level API
  - For debugging and troubleshooting

  ## Resource Management

  Resources allocated with `alloc/1` must be explicitly freed with `free/2`.
  Forgetting to free resources will cause memory leaks in the Zig port process.

  ## Example

      {:ok, pid} = NFTex.start_link()

      # Allocate table resource
      {:ok, table_id} = NFTex.Kernel.Table.alloc(pid)

      # Configure table attributes
      :ok = NFTex.Kernel.Table.set_str(pid, table_id, :name, "filter")
      :ok = NFTex.Kernel.Table.set_u32(pid, table_id, :family, 2)  # AF_INET

      # ... send to kernel via netlink ...

      # Must free when done
      :ok = NFTex.Kernel.Table.free(pid, table_id)

  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc """
  Allocates a new table resource.

  Returns `{:ok, resource_id}` on success.
  The resource must be freed with `free/2` when no longer needed.
  """
  @spec alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def alloc(pid) do
    Port.call(pid, {:table_alloc})
  end

  @doc """
  Frees a table resource.

  After calling this function, the resource_id is no longer valid.
  """
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id) do
    Port.call(pid, {:table_free, resource_id})
  end

  @doc """
  Sets a string attribute on a table.

  ## Supported attributes

  - `:name` - Table name

  ## Example

      NFTex.Kernel.Table.set_str(pid, table_id, :name, "filter")
  """
  @spec set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def set_str(pid, resource_id, attr, value) do
    Port.call(pid, {:table_set_str, resource_id, attr, value})
  end

  @doc """
  Sets a u32 attribute on a table.

  ## Supported attributes

  - `:family` - Protocol family (2 = IPv4, 10 = IPv6, etc.)
  - `:flags` - Table flags

  ## Example

      NFTex.Kernel.Table.set_u32(pid, table_id, :family, 2)  # AF_INET
  """
  @spec set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u32(pid, resource_id, attr, value) do
    Port.call(pid, {:table_set_u32, resource_id, attr, value})
  end

  @doc """
  Gets a string attribute from a table.

  ## Example

      {:ok, name} = NFTex.Kernel.Table.get_str(pid, table_id, :name)
  """
  @spec get_str(pid(), resource_id(), atom()) :: {:ok, String.t()} | {:error, term()}
  def get_str(pid, resource_id, attr) do
    Port.call(pid, {:table_get_str, resource_id, attr})
  end

  @doc """
  Gets a u32 attribute from a table.

  ## Example

      {:ok, family} = NFTex.Kernel.Table.get_u32(pid, table_id, :family)
  """
  @spec get_u32(pid(), resource_id(), atom()) :: {:ok, non_neg_integer()} | {:error, term()}
  def get_u32(pid, resource_id, attr) do
    Port.call(pid, {:table_get_u32, resource_id, attr})
  end

  @doc """
  Sends a table to the kernel via netlink.

  This function communicates with the kernel's nftables subsystem via netlink
  to add or delete a table. Requires `CAP_NET_ADMIN` capability.

  ## Arguments

  - `pid` - The NFTex port process
  - `resource_id` - The table resource ID (from `alloc/1`)
  - `cmd` - The command to perform:
    - `:add` - Create the table in the kernel
    - `:delete` - Remove the table from the kernel

  ## Returns

  - `:ok` - Operation succeeded
  - `{:error, reason}` - Operation failed

  ## Example

      # Create table
      {:ok, table_id} = NFTex.Kernel.Table.alloc(pid)
      :ok = NFTex.Kernel.Table.set_str(pid, table_id, :name, "filter")
      :ok = NFTex.Kernel.Table.set_u32(pid, table_id, :family, 2)
      :ok = NFTex.Kernel.Table.send_to_kernel(pid, table_id, :add)

      # Delete table
      :ok = NFTex.Kernel.Table.send_to_kernel(pid, table_id, :delete)
      :ok = NFTex.Kernel.Table.free(pid, table_id)

  ## Errors

  Common error reasons include:

  - `"Permission denied (EACCES)"` - Missing CAP_NET_ADMIN capability
  - `"File exists (EEXIST)"` - Table already exists (when using `:add`)
  - `"No such file or directory (ENOENT)"` - Table doesn't exist (when using `:delete`)

  """
  @spec send_to_kernel(pid(), resource_id(), :add | :delete) :: :ok | {:error, term()}
  def send_to_kernel(pid, resource_id, cmd) when cmd in [:add, :delete] do
    Port.call(pid, {:table_send_to_kernel, resource_id, cmd})
  end
end
