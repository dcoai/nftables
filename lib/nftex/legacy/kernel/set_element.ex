defmodule NFTex.Kernel.SetElement do
  @moduledoc """
  Low-level set element operations - direct libnftnl bindings.

  Set elements are the individual entries in a set. Each element has a key
  and optionally associated data (for map sets).

  ## Note on Ownership

  When an element is added to a set via `add/3`, ownership is transferred to
  the set. Do NOT free the element after adding it.

  ## Example

      # Create element with IP address key
      {:ok, elem_id} = NFTex.Kernel.SetElement.alloc(pid)
      :ok = NFTex.Kernel.SetElement.set_data(pid, elem_id, :key, <<192, 168, 1, 100>>)

      # Add to set (transfers ownership - don't free elem_id!)
      :ok = NFTex.Kernel.SetElement.add(pid, set_id, elem_id)

      # For map sets, also set data value
      {:ok, elem_id2} = NFTex.Kernel.SetElement.alloc(pid)
      :ok = NFTex.Kernel.SetElement.set_data(pid, elem_id2, :key, <<192, 168, 1, 101>>)
      :ok = NFTex.Kernel.SetElement.set_data(pid, elem_id2, :data, <<1, 0, 0, 0>>)
      :ok = NFTex.Kernel.SetElement.add(pid, set_id, elem_id2)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc "Allocates a new set element resource."
  @spec alloc(pid()) :: {:ok, resource_id()} | {:error, term()}
  def alloc(pid), do: Port.call(pid, {:set_elem_alloc})

  @doc """
  Frees a set element resource.

  WARNING: Only free elements that have NOT been added to a set.
  Once added, the set owns the element.
  """
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id), do: Port.call(pid, {:set_elem_free, resource_id})

  @doc """
  Sets binary data on a set element.

  Supported attributes:
  - `:key` - Element key (required)
  - `:data` - Element data value (for map sets)
  """
  @spec set_data(pid(), resource_id(), atom(), binary()) :: :ok | {:error, term()}
  def set_data(pid, resource_id, attr, data) do
    Port.call(pid, {:set_elem_set_data, resource_id, attr, data})
  end

  @doc """
  Sets a u32 attribute on a set element.

  Supported attributes: `:flags`, `:timeout`
  """
  @spec set_u32(pid(), resource_id(), atom(), non_neg_integer()) :: :ok | {:error, term()}
  def set_u32(pid, resource_id, attr, value) do
    Port.call(pid, {:set_elem_set_u32, resource_id, attr, value})
  end

  @doc """
  Adds a set element to a set.

  This transfers ownership of the element to the set. After calling this,
  do NOT call `free/2` on the element.

  ## Example

      {:ok, elem_id} = NFTex.Kernel.SetElement.alloc(pid)
      :ok = NFTex.Kernel.SetElement.set_data(pid, elem_id, :key, key_data)
      :ok = NFTex.Kernel.SetElement.add(pid, set_id, elem_id)
      # elem_id is now owned by set_id - don't free it!
  """
  @spec add(pid(), resource_id(), resource_id()) :: :ok | {:error, term()}
  def add(pid, set_id, elem_id) do
    Port.call(pid, {:set_elem_add, set_id, elem_id})
  end
end
