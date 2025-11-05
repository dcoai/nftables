defmodule NFTex.Table do
  @moduledoc """
  High-level table operations with automatic resource management.

  Tables are the top-level containers in nftables that organize chains, rules,
  and sets by protocol family (IPv4, IPv6, etc.). This module provides an
  idiomatic Elixir interface for creating and deleting tables with automatic
  resource cleanup.

  ## Overview

  In nftables, the hierarchy is:

      Table → Chain → Rule → Expression

  Tables organize related firewall components and are specific to a protocol
  family. For example, you might have:
  - `filter` table for IPv4 packet filtering (family: `:inet`)
  - `nat` table for NAT operations (family: `:ip`)
  - `filter6` table for IPv6 filtering (family: `:ip6`)

  ## Quick Example

      {:ok, pid} = NFTex.start_link()

      # Create a table for IPv4/IPv6 filtering
      :ok = NFTex.Table.create(pid, %{
        name: "filter",
        family: :inet
      })

      # Delete the table
      :ok = NFTex.Table.delete(pid, "filter", :inet)

  ## Protocol Families

  - `:inet` - IPv4 and IPv6 (most common)
  - `:ip` - IPv4 only
  - `:ip6` - IPv6 only
  - `:arp` - ARP
  - `:bridge` - Bridge
  - `:netdev` - Netdev (ingress filtering)

  ## Querying Tables

  To list existing tables, use `NFTex.Query.list_tables/2`:

      {:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)

  ## Integration with nft Command

  Tables created with NFTex are immediately visible via the `nft` command:

      # Create with NFTex
      NFTex.Table.create(pid, %{name: "filter", family: :inet})

      # View with nft
      $ nft list tables
      table inet filter

  ## See Also

  - `NFTex.Chain` - Create chains within tables
  - `NFTex.Rule` - Add rules to chains
  - `NFTex.Query` - Query existing tables and configuration
  - `NFTex.Kernel.Table` - Low-level table operations
  """

  alias NFTex.Kernel

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type table_spec :: %{
          name: String.t(),
          family: family(),
          flags: [atom()]
        }

  @doc """
  Create a table.

  ## Parameters

  - `name` - Table name (required)
  - `family` - Protocol family (required)
  - `flags` - Table flags (optional, default: [])

  ## Families

  - `:inet` - IPv4 and IPv6
  - `:ip` - IPv4 only
  - `:ip6` - IPv6 only
  - `:arp` - ARP
  - `:bridge` - Bridge
  - `:netdev` - Netdev (ingress)

  ## Example

      NFTex.Table.create(pid, %{
        name: "filter",
        family: :inet,
        flags: []
      })

  """
  @spec create(pid(), table_spec()) :: :ok | {:error, term()}
  def create(pid, %{name: name, family: family} = spec) do
    flags = Map.get(spec, :flags, [])

    # Allocate, configure, send to kernel, and cleanup
    with {:ok, table_id} <- Kernel.Table.alloc(pid),
         :ok <- Kernel.Table.set_str(pid, table_id, :name, name),
         :ok <- Kernel.Table.set_u32(pid, table_id, :family, family_to_int(family)),
         :ok <- maybe_set_flags(pid, table_id, flags),
         :ok <- Kernel.Table.send_to_kernel(pid, table_id, :add),
         :ok <- Kernel.Table.free(pid, table_id) do
      :ok
    else
      {:error, _reason} = error ->
        # Note: If allocation succeeded but later steps fail, the resource will be
        # cleaned up when the port process exits. For long-lived processes, consider
        # using a try/rescue to ensure cleanup.
        error
    end
  end

  @doc """
  Delete a table.

  ## Example

      NFTex.Table.delete(pid, "filter", :inet)

  """
  @spec delete(pid(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, name, family) do
    # Allocate, configure, send delete to kernel, and cleanup
    with {:ok, table_id} <- Kernel.Table.alloc(pid),
         :ok <- Kernel.Table.set_str(pid, table_id, :name, name),
         :ok <- Kernel.Table.set_u32(pid, table_id, :family, family_to_int(family)),
         :ok <- Kernel.Table.send_to_kernel(pid, table_id, :delete),
         :ok <- Kernel.Table.free(pid, table_id) do
      :ok
    else
      {:error, _reason} = error ->
        error
    end
  end

  @doc """
  List all tables.

  Returns a list of table specifications.

  ## Example

      {:ok, tables} = NFTex.Table.list(pid, :inet)
      # => [%{name: "filter", family: :inet}, ...]

  """
  @spec list(pid(), family()) :: {:ok, [table_spec()]} | {:error, term()}
  def list(_pid, _family) do
    # TODO: Implement table listing via netlink
    {:error, :not_implemented}
  end

  # Private helpers

  defp family_to_int(:inet), do: 1
  defp family_to_int(:ip), do: 2
  defp family_to_int(:ip6), do: 10
  defp family_to_int(:arp), do: 3
  defp family_to_int(:bridge), do: 7
  defp family_to_int(:netdev), do: 5

  defp maybe_set_flags(pid, table_id, []) do
    # No flags to set
    :ok
  end

  defp maybe_set_flags(pid, table_id, flags) when is_list(flags) do
    flags_int = flags_to_int(flags)
    Kernel.Table.set_u32(pid, table_id, :flags, flags_int)
  end

  defp flags_to_int(flags) do
    # TODO: Implement flag conversion when needed
    # For now, return 0 (no flags)
    _ = flags
    0
  end
end
