defmodule NFTex.Set do
  @moduledoc """
  High-level set operations for nftables.

  Sets allow efficient matching against multiple values (IP addresses, ports, etc.).
  This module provides simplified access for common set operations.

  For advanced features (maps, concatenated sets, interval sets), use
  `NFTex.Kernel.Set` and `NFTex.Kernel.SetElement`.

  ## Quick Start

      # Start NFTex
      {:ok, pid} = NFTex.start_link()

      # Create a set (currently requires low-level API)
      {:ok, set_id} = NFTex.Port.call(pid, {:set_alloc})
      :ok = NFTex.Port.call(pid, {:set_set_str, set_id, :name, "blocklist"})
      :ok = NFTex.Port.call(pid, {:set_set_str, set_id, :table, "filter"})
      :ok = NFTex.Port.call(pid, {:set_set_u32, set_id, :family, 2})  # inet
      :ok = NFTex.Port.call(pid, {:set_set_u32, set_id, :key_len, 4})  # IPv4
      :ok = NFTex.Port.call(pid, {:set_send_to_kernel, set_id, :add})
      NFTex.Port.call(pid, {:set_free, set_id})

      # Add IP addresses to blocklist
      ips = [<<192, 168, 1, 100>>, <<10, 0, 0, 50>>]
      :ok = NFTex.Set.add_elements(pid, "filter", "blocklist", :inet, ips)

      # List blocked IPs
      {:ok, elements} = NFTex.Set.list_elements(pid, "filter", "blocklist")
      for elem <- elements, do: IO.puts(elem.key_ip)

      # Remove an IP
      :ok = NFTex.Set.delete_elements(pid, "filter", "blocklist", :inet, [<<192, 168, 1, 100>>])

  ## Working Examples

  See the `examples/` directory for complete, runnable examples:
  - `examples/ip_blocklist.exs` - Dynamic IP blocklist management
  - `examples/query_tables.exs` - Querying nftables configuration

  Run them with: `mix run examples/ip_blocklist.exs`

  """

  alias NFTex.Kernel

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type key_type :: :ipv4_addr | :ipv6_addr | :ether_addr | :inet_protocol | :inet_service
  @type set_spec :: %{
          name: String.t(),
          table: String.t(),
          family: family(),
          key_type: key_type(),
          elements: [binary()]
        }

  @doc """
  Create a set with elements.

  ## Parameters

  - `name` - Set name (required)
  - `table` - Table name (required)
  - `family` - Protocol family (required)
  - `key_type` - Key data type (required)
  - `elements` - List of element keys as binaries (required)

  ## Key Types

  - `:ipv4_addr` - IPv4 address (4 bytes)
  - `:ipv6_addr` - IPv6 address (16 bytes)
  - `:ether_addr` - Ethernet MAC address (6 bytes)
  - `:inet_protocol` - IP protocol number (1 byte)
  - `:inet_service` - Port number (2 bytes)

  ## Example

      NFTex.Set.create(pid, %{
        name: "banned_ips",
        table: "filter",
        family: :inet,
        key_type: :ipv4_addr,
        elements: [
          <<192, 168, 1, 100>>,
          <<192, 168, 1, 101>>
        ]
      })

  """
  @spec create(pid(), set_spec()) :: :ok | {:error, term()}
  def create(pid, %{name: name, table: table, family: family, key_type: key_type, elements: elements}) do
    {key_type_int, key_len} = key_type_to_int_and_len(key_type)

    with {:ok, set_id} <- Kernel.Set.alloc(pid),
         :ok <- Kernel.Set.set_str(pid, set_id, :name, name),
         :ok <- Kernel.Set.set_str(pid, set_id, :table, table),
         :ok <- Kernel.Set.set_u32(pid, set_id, :family, family_to_int(family)),
         :ok <- Kernel.Set.set_u32(pid, set_id, :key_type, key_type_int),
         :ok <- Kernel.Set.set_u32(pid, set_id, :key_len, key_len),
         :ok <- add_elements(pid, set_id, elements),
         # TODO: Send to kernel via netlink
         :ok <- Kernel.Set.free(pid, set_id) do
      :ok
    end
  end

  @doc """
  Delete a set.

  ## Example

      NFTex.Set.delete(pid, "filter", "banned_ips", :inet)

  """
  @spec delete(pid(), String.t(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, table, name, family) do
    # Allocate, configure, send delete to kernel, and cleanup
    with {:ok, set_id} <- Kernel.Set.alloc(pid),
         :ok <- Kernel.Set.set_str(pid, set_id, :name, name),
         :ok <- Kernel.Set.set_str(pid, set_id, :table, table),
         :ok <- Kernel.Set.set_u32(pid, set_id, :family, family_to_int(family)),
         :ok <- Kernel.Set.send_to_kernel(pid, set_id, :delete),
         :ok <- Kernel.Set.free(pid, set_id) do
      :ok
    else
      {:error, _reason} = error ->
        error
    end
  end

  @doc """
  Add elements to an existing set.

  ## Example

      NFTex.Set.add_elements(pid, "filter", "banned_ips", :inet, [
        <<192, 168, 1, 200>>
      ])

  """
  @spec add_elements(pid(), String.t(), String.t(), family(), [binary()]) ::
          :ok | {:error, term()}
  def add_elements(pid, table, name, family, elements) when is_list(elements) do
    family_int = family_to_int(family)
    timeout = 5000

    with {:ok, set_id} <- NFTex.Port.call(pid, {:set_alloc}, timeout),
         :ok <- NFTex.Port.call(pid, {:set_set_str, set_id, :name, name}, timeout),
         :ok <- NFTex.Port.call(pid, {:set_set_str, set_id, :table, table}, timeout) do

      # Add all elements
      elem_result = Enum.reduce_while(elements, :ok, fn key, :ok ->
        with {:ok, elem_id} <- NFTex.Port.call(pid, {:set_elem_alloc}, timeout),
             :ok <- NFTex.Port.call(pid, {:set_elem_set_data, elem_id, :key, key}, timeout),
             :ok <- NFTex.Port.call(pid, {:set_elem_add, set_id, elem_id}, timeout) do
          {:cont, :ok}
        else
          error -> {:halt, error}
        end
      end)

      case elem_result do
        :ok ->
          NFTex.Port.call(pid, {:set_elem_send_to_kernel, set_id, :add, family_int}, timeout)

        error ->
          error
      end
    end
  end

  @doc """
  Remove elements from a set.

  ## Example

      NFTex.Set.delete_elements(pid, "filter", "banned_ips", :inet, [
        <<192, 168, 1, 100>>
      ])

  """
  @spec delete_elements(pid(), String.t(), String.t(), family(), [binary()]) ::
          :ok | {:error, term()}
  def delete_elements(pid, table, name, family, elements) when is_list(elements) do
    NFTex.Query.delete_set_elements(pid, table, name, elements, family: family)
  end

  @doc """
  List all sets for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, sets} = NFTex.Set.list(pid)
      {:ok, sets} = NFTex.Set.list(pid, family: :inet6)

      for set <- sets do
        IO.puts("Set: \#{set.name} in table \#{set.table}")
      end

  """
  @spec list(pid(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list(pid, opts \\ []) do
    NFTex.Query.list_sets(pid, opts)
  end

  @doc """
  List elements in a specific set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, elements} = NFTex.Set.list_elements(pid, "filter", "banned_ips")

      for elem <- elements do
        IO.puts("IP: \#{elem.key_ip}")
      end

  """
  @spec list_elements(pid(), String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_elements(pid, table, set_name, opts \\ []) do
    NFTex.Query.list_set_elements(pid, table, set_name, opts)
  end

  @doc """
  Check if a set exists.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `family` - Protocol family (default: `:inet`)

  ## Examples

      if NFTex.Set.exists?(pid, "filter", "banned_ips", :inet) do
        IO.puts("Set exists")
      end

  """
  @spec exists?(pid(), String.t(), String.t(), family()) :: boolean()
  def exists?(pid, table, set_name, family \\ :inet) do
    case NFTex.Query.list_sets(pid, family: family) do
      {:ok, sets} ->
        Enum.any?(sets, fn set ->
          set.name == set_name and set.table == table
        end)

      {:error, _} ->
        false
    end
  end

  # Private helpers

  defp family_to_int(:inet), do: 1
  defp family_to_int(:ip), do: 2
  defp family_to_int(:ip6), do: 10
  defp family_to_int(:arp), do: 3
  defp family_to_int(:bridge), do: 7
  defp family_to_int(:netdev), do: 5

  defp key_type_to_int_and_len(:ipv4_addr), do: {7, 4}
  defp key_type_to_int_and_len(:ipv6_addr), do: {8, 16}
  defp key_type_to_int_and_len(:ether_addr), do: {9, 6}
  defp key_type_to_int_and_len(:inet_protocol), do: {12, 1}
  defp key_type_to_int_and_len(:inet_service), do: {13, 2}

  defp add_elements(_pid, _set_id, []), do: :ok

  defp add_elements(pid, set_id, [element | rest]) do
    with {:ok, elem_id} <- Kernel.SetElement.alloc(pid),
         :ok <- Kernel.SetElement.set_data(pid, elem_id, :key, element),
         :ok <- Kernel.SetElement.add(pid, set_id, elem_id) do
      # Element now owned by set, continue with rest
      add_elements(pid, set_id, rest)
    end
  end
end
