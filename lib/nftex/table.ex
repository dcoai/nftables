defmodule NFTex.Table do
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

      {:ok, pid} = NFTex.start_link()

      # Add a table for IPv4/IPv6 filtering
      :ok = NFTex.Table.add(pid, %{
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
      NFTex.Table.add(pid, %{name: "filter", family: :inet})

      # View with nft
      $ nft list tables
      table inet filter

  ## See Also

  - `NFTex.Chain` - Create chains within tables
  - `NFTex.Rule` - Add rules to chains
  - `NFTex.Query` - Query existing tables and configuration
  """

  alias NFTex.{Port, JSONBuilder}

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev
  @type table_spec :: %{
          name: String.t(),
          family: family()
        }

  @doc """
  Add a table.

  ## Parameters

  - `name` - Table name (required)
  - `family` - Protocol family (required)

  ## Families

  - `:inet` - IPv4 and IPv6
  - `:ip` - IPv4 only
  - `:ip6` - IPv6 only
  - `:arp` - ARP
  - `:bridge` - Bridge
  - `:netdev` - Netdev (ingress)

  ## Example

      NFTex.Table.add(pid, %{
        name: "filter",
        family: :inet
      })

  """
  @spec add(pid(), table_spec()) :: :ok | {:error, term()}
  def add(pid, %{name: name, family: family}) when is_binary(name) do
    # Build JSON command
    cmd = JSONBuilder.add_table(family, name)
    json = Jason.encode!(cmd)

    # Send to port
    case Port.call(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
        case Jason.decode(response_json) do
          {:ok, %{"nftables" => _}} ->
            :ok

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Delete a table.

  This will also delete all chains, rules, and sets within the table.

  ## Example

      NFTex.Table.delete(pid, "filter", :inet)

  """
  @spec delete(pid(), String.t(), family()) :: :ok | {:error, term()}
  def delete(pid, name, family) when is_binary(name) do
    # Build JSON command
    cmd = JSONBuilder.delete_table(family, name)
    json = Jason.encode!(cmd)

    # Send to port
    case Port.call(pid, json) do
      {:ok, ""} ->
        # Empty response means success
        :ok

      {:ok, response_json} ->
        # Parse response to check for errors
        case Jason.decode(response_json) do
          {:ok, %{"nftables" => _}} ->
            :ok

          {:ok, %{"error" => error}} ->
            {:error, error}

          {:error, reason} ->
            {:error, {:json_decode_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Build a JSON command to add a table (without executing).

  Returns the JSON string that would be sent to add a table.
  Useful for batching, remote execution, or inspection.

  ## Parameters

  - `table_spec` - Map with `:name` and `:family` keys

  ## Returns

  JSON string containing the table add command

  ## Examples

      # Build command
      json = NFTex.Table.build_add(%{name: "filter", family: :inet})
      #=> "{\"nftables\":[{\"add\":{\"table\":{...}}}]}"

      # Use in batch
      batch =
        Batch.new()
        |> Batch.add(Table.build_add(%{name: "filter", family: :inet}))
        |> Batch.add(Table.build_add(%{name: "nat", family: :inet}))

      # Execute later
      NFTex.Executor.execute(json)

      # Send to remote node
      MyTransport.send_to_node("firewall-1", json)
  """
  @spec build_add(table_spec()) :: binary()
  def build_add(%{name: name, family: family}) when is_binary(name) do
    cmd = JSONBuilder.add_table(family, name)
    Jason.encode!(cmd)
  end

  @doc """
  Build a JSON command to delete a table (without executing).

  Returns the JSON string that would be sent to delete a table.

  ## Parameters

  - `name` - Table name
  - `family` - Protocol family

  ## Returns

  JSON string containing the table delete command

  ## Examples

      json = NFTex.Table.build_delete("filter", :inet)
      NFTex.Executor.execute(json)
  """
  @spec build_delete(String.t(), family()) :: binary()
  def build_delete(name, family) when is_binary(name) do
    cmd = JSONBuilder.delete_table(family, name)
    Jason.encode!(cmd)
  end

  @doc """
  Check if a table exists.

  ## Parameters

  - `pid` - NFTex process pid
  - `name` - Table name (string)
  - `family` - Protocol family (default: `:inet`)

  ## Examples

      if NFTex.Table.exists?(pid, "filter", :inet) do
        IO.puts("Table exists")
      end

  """
  @spec exists?(pid(), String.t(), family()) :: boolean()
  def exists?(pid, name, family \\ :inet) do
    case NFTex.Query.list_tables(pid, family: family) do
      {:ok, tables} ->
        Enum.any?(tables, fn table ->
          table.name == name
        end)

      {:error, _} ->
        false
    end
  end
end
