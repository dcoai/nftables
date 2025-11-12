defmodule NFTablesEx.Table do
  @moduledoc """
  High-level table operations.

  Tables are the top-level containers in nftables that organize chains, rules,
  and sets by protocol family (IPv4, IPv6, etc.). This module provides an
  idiomatic Elixir interface for creating and deleting tables.

  ## Overview

  In nftables, the hierarchy is:

      Table → Chain → Rule → Expression

  Tables organize related firewall components and are specific to a protocol
  family. For example, you might have:
  - `filter` table for IPv4/IPv6 packet filtering (family: `:inet`)
  - `nat` table for NAT operations (family: `:ip`)
  - `filter6` table for IPv6 filtering (family: `:ip6`)

  ## Quick Example

      {:ok, pid} = NFTablesEx.start_link()

      # Add a table for IPv4/IPv6 filtering
      :ok = NFTablesEx.Table.add(pid, %{
        name: "filter",
        family: :inet
      })

      # Delete the table
      :ok = NFTablesEx.Table.delete(pid, "filter", :inet)

  ## Protocol Families

  - `:inet` - IPv4 and IPv6 (most common)
  - `:ip` - IPv4 only
  - `:ip6` - IPv6 only
  - `:arp` - ARP
  - `:bridge` - Bridge
  - `:netdev` - Netdev (ingress filtering)

  ## Querying Tables

  To list existing tables, use `NFTablesEx.Query.list_tables/2`:

      {:ok, tables} = NFTablesEx.Query.fetch_tables(pid, family: :inet)

  ## Integration with nft Command

  Tables created with NFTex are immediately visible via the `nft` command:

      # Create with NFTex
      NFTablesEx.Table.add(pid, %{name: "filter", family: :inet})

      # View with nft
      $ nft list tables
      table inet filter

  ## See Also

  - `NFTablesEx.Chain` - Create chains within tables
  - `NFTablesEx.Rule` - Add rules to chains
  - `NFTablesEx.Query` - Query existing tables and configuration
  """

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type table_spec :: %{
          name: String.t(),
          family: family()
        }

  @doc """
  Add a table.

  ## Parameters

  - `pid` - NFTex process pid
  - `table_spec` - Map with `:name` and `:family` keys

  ## Families

  - `:inet` - IPv4 and IPv6
  - `:ip` - IPv4 only
  - `:ip6` - IPv6 only
  - `:arp` - ARP
  - `:bridge` - Bridge
  - `:netdev` - Netdev (ingress)

  ## Example

      :ok = NFTablesEx.Table.add(pid, %{
        name: "filter",
        family: :inet
      })

  """
  @spec add(pid(), table_spec()) :: :ok | {:error, term()}
  def add(pid, %{name: name} = spec) when is_binary(name) do
    build_add(spec)
    |> NFTablesEx.Executor.execute(pid: pid)
    |> NFTablesEx.Decoder.decode()
  end

  @doc """
  Delete a table.

  This will also delete all chains, rules, and sets within the table.

  ## Parameters

  - `pid` - NFTex process pid
  - `name` - Table name (string)
  - `family` - Protocol family (default: `:inet`)

  ## Example

      :ok = NFTablesEx.Table.delete(pid, "filter", :inet)

  """
  @spec delete(pid(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, name, family \\ :inet) when is_binary(name) do
    build_delete(name, family)
    |> NFTablesEx.Executor.execute(pid: pid)
    |> NFTablesEx.Decoder.decode()
  end

  @doc """
  Build a command map to add a table (without executing).

  Returns a map that would be sent to add a table.
  Useful for batching, remote execution, or inspection.

  ## Parameters

  - `table_spec` - Map with `:name` and `:family` keys

  ## Returns

  Map containing the table add command

  ## Examples

      # Build command
      cmd = NFTablesEx.Table.build_add(%{name: "filter", family: :inet})
      #=> %{"nftables" => [%{"add" => %{"table" => ...}}]}

      # Use in batch
      batch =
        Batch.new()
        |> Batch.add(Table.build_add(%{name: "filter", family: :inet}))
        |> Batch.add(Table.build_add(%{name: "nat", family: :inet}))

      # Execute later
      NFTablesEx.Executor.execute(cmd)

      # Send to remote node
      MyTransport.send_to_node("firewall-1", cmd)
  """
  @spec build_add(table_spec()) :: map()
  def build_add(%{name: name, family: family}) when is_binary(name) do
    %{
      "nftables" => [
        %{
          "add" => %{
            "table" => %{
              "family" => family,
              "name" => name
            }
          }
        }
      ]
    }
  end

  @doc """
  Build a command map to delete a table (without executing).

  Returns a map that would be sent to delete a table.

  ## Parameters

  - `name` - Table name
  - `family` - Protocol family

  ## Returns

  Map containing the table delete command

  ## Examples

      cmd = NFTablesEx.Table.build_delete("filter", :inet)
      NFTablesEx.Executor.execute(cmd)
  """
  @spec build_delete(String.t(), family()) :: map()
  def build_delete(name, family) when is_binary(name) do
    %{
      "nftables" => [
        %{
          "delete" => %{
            "table" => %{
              "family" => family,
              "name" => name
            }
          }
        }
      ]
    }
  end

end
