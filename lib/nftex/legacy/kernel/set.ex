defmodule NFTex.Kernel.Set do
  @moduledoc """
  Low-level set operations - direct libnftnl bindings.

  Sets allow efficient matching against multiple values. They can be:
  - Simple sets (IP addresses, ports, etc.)
  - Maps (sets with associated data values)
  - Interval sets (ranges like 192.168.0.0/16)
  - Concatenated sets (multi-field keys like IP + port)

  ## Example

      # Create simple IP set
      {:ok, set_id} = NFTex.Kernel.Set.alloc(pid)
      :ok = NFTex.Kernel.Set.set_str(pid, set_id, :name, "banned_ips")
      :ok = NFTex.Kernel.Set.set_str(pid, set_id, :table, "filter")
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :family, 2)      # IPv4
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_type, 7)    # IPv4 addr
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_len, 4)

      # Add elements
      {:ok, elem_id} = NFTex.Kernel.SetElement.alloc(pid)
      :ok = NFTex.Kernel.SetElement.set_data(pid, elem_id, :key, <<192, 168, 1, 100>>)
      :ok = NFTex.Kernel.SetElement.add(pid, set_id, elem_id)

      # ... send to kernel ...
      :ok = NFTex.Kernel.Set.free(pid, set_id)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc "Allocates a new set resource."
  @spec alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def alloc(pid), do: Port.call(pid, {:set_alloc})

  @doc "Frees a set resource."
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id), do: Port.call(pid, {:set_free, resource_id})

  @doc """
  Sets a string attribute on a set.

  Supported attributes: `:name`, `:table`
  """
  @spec set_str(pid(), resource_id(), atom(), String.t()) :: :ok | {:error, term()}
  def set_str(pid, resource_id, attr, value) do
    Port.call(pid, {:set_set_str, resource_id, attr, value})
  end

  @doc """
  Sets a u32 attribute on a set.

  Supported attributes: `:family`, `:key_type`, `:key_len`, `:data_type`,
  `:data_len`, `:flags`, `:id`, `:policy`, `:desc_size`
  """
  @spec set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u32(pid, resource_id, attr, value) do
    Port.call(pid, {:set_set_u32, resource_id, attr, value})
  end

  @doc """
  Sends a set definition to the kernel via netlink.

  This creates or deletes the set structure itself (not its elements).
  Use `send_elements_to_kernel/3` to add/delete the actual elements.

  Requires `CAP_NET_ADMIN` capability.

  ## Arguments

  - `pid` - The NFTex port process
  - `resource_id` - The set resource ID (from `alloc/1`)
  - `cmd` - The command to perform:
    - `:add` - Create the set in the kernel
    - `:delete` - Remove the set from the kernel

  ## Returns

  - `:ok` - Operation succeeded
  - `{:error, reason}` - Operation failed

  ## Example

      # Create set definition
      {:ok, set_id} = NFTex.Kernel.Set.alloc(pid)
      :ok = NFTex.Kernel.Set.set_str(pid, set_id, :table, "filter")
      :ok = NFTex.Kernel.Set.set_str(pid, set_id, :name, "banned_ips")
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :family, 2)
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_type, 7)
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :key_len, 4)

      # Send set definition to kernel
      :ok = NFTex.Kernel.Set.send_to_kernel(pid, set_id, :add)

      # Now add elements (see send_elements_to_kernel/3)

  ## Errors

  Common error reasons include:

  - `"Permission denied (EACCES)"` - Missing CAP_NET_ADMIN capability
  - `"File exists (EEXIST)"` - Set already exists (when using `:add`)
  - `"No such file or directory (ENOENT)"` - Set doesn't exist (when using `:delete`)

  """
  @spec send_to_kernel(pid(), resource_id(), :add | :delete) :: :ok | {:error, term()}
  def send_to_kernel(pid, resource_id, cmd) when cmd in [:add, :delete] do
    Port.call(pid, {:set_send_to_kernel, resource_id, cmd})
  end

  @doc """
  Sends set elements to the kernel via netlink.

  This adds or removes elements from an existing set. The set definition
  must already exist in the kernel (created via `send_to_kernel/3`).

  Elements must be added to the set resource using `NFTex.Kernel.SetElement`
  before calling this function.

  Requires `CAP_NET_ADMIN` capability.

  ## Arguments

  - `pid` - The NFTex port process
  - `resource_id` - The set resource ID containing elements
  - `cmd` - The command to perform:
    - `:add` - Add elements to the set
    - `:delete` - Remove elements from the set

  ## Returns

  - `:ok` - Operation succeeded
  - `{:error, reason}` - Operation failed

  ## Example

      # Set must already exist in kernel
      {:ok, set_id} = NFTex.Kernel.Set.alloc(pid)
      :ok = NFTex.Kernel.Set.set_str(pid, set_id, :table, "filter")
      :ok = NFTex.Kernel.Set.set_str(pid, set_id, :name, "banned_ips")
      :ok = NFTex.Kernel.Set.set_u32(pid, set_id, :family, 2)

      # Add elements to set resource
      {:ok, elem_id} = NFTex.Kernel.SetElement.alloc(pid)
      :ok = NFTex.Kernel.SetElement.set_data(pid, elem_id, :key, <<192, 168, 1, 100>>)
      :ok = NFTex.Kernel.SetElement.add(pid, set_id, elem_id)

      # Send elements to kernel
      :ok = NFTex.Kernel.Set.send_elements_to_kernel(pid, set_id, :add)

  ## Errors

  Common error reasons include:

  - `"Permission denied (EACCES)"` - Missing CAP_NET_ADMIN capability
  - `"No such file or directory (ENOENT)"` - Set doesn't exist in kernel

  """
  @spec send_elements_to_kernel(pid(), resource_id(), :add | :delete) :: :ok | {:error, term()}
  def send_elements_to_kernel(pid, resource_id, cmd) when cmd in [:add, :delete] do
    Port.call(pid, {:set_elem_send_to_kernel, resource_id, cmd})
  end
end
