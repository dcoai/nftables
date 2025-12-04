defmodule NFTables.Query do
  @moduledoc """
  Command builders for querying nftables resources.

  This module provides pure functions that build nftables JSON commands for
  read operations. Commands are meant to be piped through NFTables.Local for execution
  and Decoder for transformation.

  ## Pipeline Architecture

  ```
  Query.list_tables(family: :inet)     # Build command (pure function)
  |> NFTables.Local.submit(pid: pid)   # Execute & JSON decode
  |> Decoder.decode()                  # Transform to idiomatic Elixir
  ```

  ## Examples

      # List all tables
      {:ok, %{tables: tables}} =
        Query.list_tables(family: :inet)
        |> NFTables.Local.submit(pid: pid)
        |> Decoder.decode()

      # List rules in a specific chain
      {:ok, %{rules: rules}} =
        Query.list_rules("filter", "INPUT")
        |> NFTables.Local.submit(pid: pid)
        |> Decoder.decode()

      # List entire ruleset
      {:ok, %{tables: tables, chains: chains, rules: rules, sets: sets}} =
        Query.list_ruleset(family: :inet)
        |> NFTables.Local.submit(pid: pid)
        |> Decoder.decode()

      # Build command for remote execution
      cmd = Query.list_tables(family: :inet)
      MyTransport.send_to_node("firewall-1", cmd)
  """

  @type family :: :inet | :ip | :ip6 | :arp | :bridge | :netdev

  ## Command Builders

  @doc """
  Build a command map to list tables.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Options

  - `:family` - Protocol family (optional)

  ## Examples

      # List all tables
      Query.list_tables()
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()

      # List tables for specific family
      Query.list_tables(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
  """
  @spec list_tables(keyword()) :: map()
  def list_tables(opts \\ []) when is_list(opts) do
    family = Keyword.get(opts, :family)

    if family do
      %{"nftables" => [%{"list" => %{"tables" => %{"family" => family}}}]}
    else
      %{"nftables" => [%{"list" => %{"tables" => %{}}}]}
    end
  end

  @doc """
  Build a command map to list chains.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Options

  - `:family` - Protocol family (optional)

  ## Examples

      Query.list_chains(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
  """
  @spec list_chains(keyword()) :: map()
  def list_chains(opts \\ []) when is_list(opts) do
    family = Keyword.get(opts, :family)

    if family do
      %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => family}}}]}
    else
      %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
    end
  end

  @doc """
  Build a command map to list rules.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Parameters

  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)

  Or:

  - `table` - Table name (string)
  - `chain` - Chain name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)

  ## Examples

      # List all rules for a family
      Query.list_rules(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()

      # List rules in a specific chain
      Query.list_rules("filter", "INPUT")
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()

      # With options
      Query.list_rules("filter", "INPUT", family: :inet6)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
  """
  @spec list_rules(keyword()) :: map()
  @spec list_rules(String.t(), String.t()) :: map()
  @spec list_rules(String.t(), String.t(), keyword()) :: map()
  def list_rules(opts) when is_list(opts) do
    family = Keyword.get(opts, :family, :inet)

    if family do
      %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => family}}}]}
    else
      %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
    end
  end

  def list_rules(table, chain) when is_binary(table) and is_binary(chain) do
    list_rules(table, chain, [])
  end

  def list_rules(table, chain, opts)
      when is_binary(table) and is_binary(chain) and is_list(opts) do
    family = Keyword.get(opts, :family, :inet)

    %{
      "nftables" => [
        %{
          "list" => %{
            "chain" => %{
              "family" => family,
              "table" => table,
              "name" => chain
            }
          }
        }
      ]
    }
  end

  @doc """
  Build a command map to list sets.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Options

  - `:family` - Protocol family (optional)

  ## Examples

      Query.list_sets(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
  """
  @spec list_sets(keyword()) :: map()
  def list_sets(opts \\ []) when is_list(opts) do
    family = Keyword.get(opts, :family)

    if family do
      %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => family}}}]}
    else
      %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
    end
  end

  @doc """
  Build a command map to list set elements.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Parameters

  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)

  ## Examples

      Query.list_set_elements("filter", "blocklist")
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()

      Query.list_set_elements("filter", "blocklist", family: :inet6)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
  """
  @spec list_set_elements(String.t(), String.t(), keyword()) :: map()
  def list_set_elements(table, set_name, opts \\ [])
      when is_binary(table) and is_binary(set_name) and is_list(opts) do
    family = Keyword.get(opts, :family, :inet)

    %{
      "nftables" => [
        %{
          "list" => %{
            "set" => %{
              "family" => family,
              "table" => table,
              "name" => set_name
            }
          }
        }
      ]
    }
  end

  @doc """
  Build a command map to list the entire ruleset.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Options

  - `:family` - Protocol family (optional, default: list all families)

  ## Examples

      # List entire ruleset
      Query.list_ruleset()
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
      #=> {:ok, %{
      #     tables: [...],
      #     chains: [...],
      #     rules: [...],
      #     sets: [...]
      #   }}

      # List ruleset for specific family
      Query.list_ruleset(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
  """
  @spec list_ruleset(keyword()) :: map()
  def list_ruleset(opts \\ []) do
    family = Keyword.get(opts, :family)

    if family do
      %{"nftables" => [%{"list" => %{"ruleset" => %{"family" => family}}}]}
    else
      %{"nftables" => [%{"list" => %{"ruleset" => %{}}}]}
    end
  end

  @doc """
  Build a command map to flush ruleset.

  Returns a map that can be piped to NFTables.Local.submit/2.

  ## Options

  - `:family` - Protocol family (optional, default: flush all families)

  ## Examples

      # Flush entire ruleset
      Query.flush_ruleset()
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
      #=> :ok

      # Flush only specific family
      Query.flush_ruleset(family: :inet)
      |> NFTables.Local.submit(pid: pid)
      |> Decoder.decode()
      #=> :ok
  """
  @spec flush_ruleset(keyword()) :: map()
  def flush_ruleset(opts \\ []) do
    family = Keyword.get(opts, :family)

    if family do
      %{"nftables" => [%{"flush" => %{"ruleset" => %{"family" => family}}}]}
    else
      %{"nftables" => [%{"flush" => %{"ruleset" => %{}}}]}
    end
  end

  ## Write Operations

  @doc """
  Delete elements from a set.

  ## Parameters

  - `pid` - NFTables process pid
  - `table` - Table name
  - `set_name` - Set name
  - `elements` - List of element values (strings)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Example

      :ok = NFTables.Query.delete_set_elements(pid, "filter", "blocked_ips", ["192.168.1.100"])
  """
  @spec delete_set_elements(pid(), String.t(), String.t(), [String.t()], keyword()) ::
          :ok | {:error, term()}
  def delete_set_elements(pid, table, set_name, elements, opts \\ []) when is_list(elements) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    # Build command map
    cmd = %{
      "nftables" => [
        %{
          "delete" => %{
            "element" => %{
              "family" => family,
              "table" => table,
              "name" => set_name,
              "elem" => elements
            }
          }
        }
      ]
    }

    # Execute via NFTables.Local and decode
    NFTables.Local.submit(cmd, pid: pid, timeout: timeout)
    |> NFTables.Decoder.decode()
  end
end
