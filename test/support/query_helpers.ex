defmodule NFTables.QueryHelpers do
  @moduledoc """
  Test helper functions for the new Query/Local/Decoder pipeline pattern.

  These helpers provide convenience functions for tests while maintaining
  the new architecture.
  """

  alias NFTables.{Query, Local, Decoder}

  @doc """
  List rules in a specific chain (convenience wrapper for tests).

  ## Examples

      {:ok, rules} = QueryHelpers.list_rules(pid, "filter", "INPUT", family: :inet)
  """
  @spec list_rules(pid(), String.t(), String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_rules(pid, table, chain, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    case Query.list_rules(table, chain, family: family)
         |> Local.submit(pid: pid, timeout: timeout)
         |> Decoder.decode() do
      {:ok, decoded} -> {:ok, Map.get(decoded, :rules, [])}
      :ok -> {:ok, []}
      error -> error
    end
  end

  @doc """
  Check if a chain exists (convenience wrapper for tests).

  ## Examples

      assert QueryHelpers.chain_exists?(pid, "filter", "INPUT", :inet)
  """
  @spec chain_exists?(pid(), String.t(), String.t(), atom()) :: boolean()
  def chain_exists?(pid, table, chain_name, family \\ :inet) do
    # Try to list rules in the chain - if the chain doesn't exist, this will fail
    case Query.list_rules(table, chain_name, family: family)
         |> Local.submit(pid: pid)
         |> Decoder.decode() do
      {:ok, _decoded} ->
        # Chain exists (even if it has no rules)
        true

      :ok ->
        # Empty response means chain exists but has no rules
        true

      {:error, _reason} ->
        # Error means chain doesn't exist
        false

      _ ->
        false
    end
  end

  @doc """
  List chains for a given family (convenience wrapper for tests).

  ## Examples

      {:ok, chains} = QueryHelpers.list_chains(pid, family: :inet)
  """
  @spec list_chains(pid(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_chains(pid, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    case Query.list_chains(family: family)
         |> Local.submit(pid: pid, timeout: timeout)
         |> Decoder.decode() do
      {:ok, decoded} -> {:ok, Map.get(decoded, :chains, [])}
      :ok -> {:ok, []}
      error -> error
    end
  end

  @doc """
  Check if a set exists (convenience wrapper for tests).

  ## Examples

      assert QueryHelpers.set_exists?(pid, "filter", "blocklist", :inet)
  """
  @spec set_exists?(pid(), String.t(), String.t(), atom()) :: boolean()
  def set_exists?(pid, table, set_name, family \\ :inet) do
    case Query.list_sets(family: family)
         |> Local.submit(pid: pid)
         |> Decoder.decode() do
      {:ok, decoded} ->
        sets = Map.get(decoded, :sets, [])
        Enum.any?(sets, fn s -> s.name == set_name and s.table == table end)

      :ok ->
        false

      _ ->
        false
    end
  end

  @doc """
  List sets for a given family (convenience wrapper for tests).

  ## Examples

      {:ok, sets} = QueryHelpers.list_sets(pid, family: :inet)
  """
  @spec list_sets(pid(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_sets(pid, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    case Query.list_sets(family: family)
         |> Local.submit(pid: pid, timeout: timeout)
         |> Decoder.decode() do
      {:ok, decoded} -> {:ok, Map.get(decoded, :sets, [])}
      :ok -> {:ok, []}
      error -> error
    end
  end

  @doc """
  List elements in a set (convenience wrapper for tests).

  ## Examples

      {:ok, elements} = QueryHelpers.list_set_elements(pid, "filter", "blocklist")
  """
  @spec list_set_elements(pid(), String.t(), String.t(), keyword()) ::
          {:ok, [term()]} | {:error, term()}
  def list_set_elements(pid, table, set_name, opts \\ []) do
    family = Keyword.get(opts, :family, :inet)
    timeout = Keyword.get(opts, :timeout, 5000)

    case Query.list_set_elements(table, set_name, family: family)
         |> Local.submit(pid: pid, timeout: timeout)
         |> Decoder.decode() do
      {:ok, decoded} ->
        # Set elements are in the :set_elements key
        {:ok, Map.get(decoded, :set_elements, [])}

      :ok ->
        {:ok, []}

      error ->
        error
    end
  end

  @doc """
  Check if a table exists (convenience wrapper for tests).

  ## Examples

      assert QueryHelpers.table_exists?(pid, "filter", :inet)
  """
  @spec table_exists?(pid(), String.t(), atom()) :: boolean()
  def table_exists?(pid, table_name, family \\ :inet) do
    case Query.list_tables(family: family)
         |> Local.submit(pid: pid)
         |> Decoder.decode() do
      {:ok, decoded} ->
        tables = Map.get(decoded, :tables, [])
        Enum.any?(tables, fn t -> t.name == table_name end)

      _ ->
        false
    end
  end
end
