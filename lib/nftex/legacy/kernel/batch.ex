defmodule NFTex.Kernel.Batch do
  @moduledoc """
  Low-level batch operations - direct libnftnl bindings.

  Batches are used to build netlink messages for communication with the kernel.
  They allow multiple operations to be sent atomically.

  ## Parameters

  - `page_size` - Size of each page in bytes (typically 4096)
  - `max_pages` - Maximum number of pages (typically 20)

  ## Example

      {:ok, batch_id} = NFTex.Kernel.Batch.alloc(pid, 4096, 20)

      # Build and add messages to batch...
      # (requires netlink operations - not yet fully implemented)

      :ok = NFTex.Kernel.Batch.free(pid, batch_id)
  """

  alias NFTex.Port

  @type resource_id :: non_neg_integer()

  @doc """
  Allocates a new batch resource.

  ## Parameters

  - `page_size` - Size of each page (default: 4096)
  - `max_pages` - Maximum number of pages (default: 20)
  """
  @spec alloc(pid(), non_neg_integer(), non_neg_integer()) ::
          {:ok, resource_id()} | {:error, term()}
  def alloc(pid, page_size \\ 4096, max_pages \\ 20) do
    Port.call(pid, {:batch_alloc, page_size, max_pages})
  end

  @doc "Frees a batch resource."
  @spec free(pid(), resource_id()) :: :ok | {:error, term()}
  def free(pid, resource_id), do: Port.call(pid, {:batch_free, resource_id})
end
