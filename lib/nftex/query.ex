defmodule NFTex.Query do
  @moduledoc """
  High-level API for querying nftables resources.

  Provides convenient functions for listing tables, chains, rules, sets,
  and set elements with automatic parsing of responses.

  ## Quick Start

      {:ok, pid} = NFTex.start_link()

      # List all tables
      {:ok, tables} = NFTex.Query.list_tables(pid, family: :inet)

      # List all sets
      {:ok, sets} = NFTex.Query.list_sets(pid, family: :inet)

      # List elements in a specific set
      {:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "blocklist")

      # Elements are automatically parsed
      for elem <- elements do
        IO.puts("IP: \#{elem.key_ip}, Hex: \#{elem.key_hex}, Flags: \#{elem.flags}")
      end

  ## Examples

  See `examples/query_tables.exs` for a complete example showing how to
  query and inspect your nftables configuration.

  Run it with: `mix run examples/query_tables.exs`
  """

  alias NFTex.Port

  @type family :: :inet | :inet6 | :arp | :bridge | :netdev | non_neg_integer()
  @type result(t) :: {:ok, t} | {:error, String.t()}

  # Family atom to integer mapping
  @family_map %{
    inet: 2,
    ip: 2,
    ipv4: 2,
    inet6: 10,
    ip6: 10,
    ipv6: 10,
    arp: 3,
    bridge: 7,
    netdev: 5
  }

  ## Table Operations

  @doc """
  List all tables for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, tables} = NFTex.Query.list_tables(pid)
      {:ok, tables} = NFTex.Query.list_tables(pid, family: :inet6)
      {:ok, tables} = NFTex.Query.list_tables(pid, parse: false)
  """
  @spec list_tables(pid(), keyword()) :: result([map()])
  def list_tables(pid, opts \\ []) do
    family = resolve_family(Keyword.get(opts, :family, :inet))
    timeout = Keyword.get(opts, :timeout, 5000)
    parse = Keyword.get(opts, :parse, true)

    case Port.call(pid, {:table_list, family}, timeout) do
      {:ok, tables} when parse ->
        {:ok, Enum.map(tables, &parse_table/1)}

      {:ok, tables} ->
        {:ok, tables}

      error ->
        error
    end
  end

  ## Chain Operations

  @doc """
  List all chains for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, chains} = NFTex.Query.list_chains(pid)
      {:ok, chains} = NFTex.Query.list_chains(pid, family: :inet6)
  """
  @spec list_chains(pid(), keyword()) :: result([map()])
  def list_chains(pid, opts \\ []) do
    family = resolve_family(Keyword.get(opts, :family, :inet))
    timeout = Keyword.get(opts, :timeout, 5000)
    parse = Keyword.get(opts, :parse, true)

    case Port.call(pid, {:chain_list, family}, timeout) do
      {:ok, chains} when parse ->
        {:ok, Enum.map(chains, &parse_chain/1)}

      {:ok, chains} ->
        {:ok, chains}

      error ->
        error
    end
  end

  ## Rule Operations

  @doc """
  List all rules for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, rules} = NFTex.Query.list_rules(pid)
      {:ok, rules} = NFTex.Query.list_rules(pid, family: :inet6)
  """
  @spec list_rules(pid(), keyword()) :: result([map()])
  def list_rules(pid, opts \\ []) do
    family = resolve_family(Keyword.get(opts, :family, :inet))
    timeout = Keyword.get(opts, :timeout, 5000)
    parse = Keyword.get(opts, :parse, true)

    case Port.call(pid, {:rule_list, family}, timeout) do
      {:ok, rules} when parse ->
        {:ok, Enum.map(rules, &parse_rule/1)}

      {:ok, rules} ->
        {:ok, rules}

      error ->
        error
    end
  end

  ## Set Operations

  @doc """
  List all sets for a given protocol family.

  ## Parameters

  - `pid` - NFTex process pid
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, sets} = NFTex.Query.list_sets(pid)
      {:ok, sets} = NFTex.Query.list_sets(pid, family: :inet6)
  """
  @spec list_sets(pid(), keyword()) :: result([map()])
  def list_sets(pid, opts \\ []) do
    family = resolve_family(Keyword.get(opts, :family, :inet))
    timeout = Keyword.get(opts, :timeout, 5000)
    parse = Keyword.get(opts, :parse, true)

    case Port.call(pid, {:set_list, family}, timeout) do
      {:ok, sets} when parse ->
        {:ok, Enum.map(sets, &parse_set/1)}

      {:ok, sets} ->
        {:ok, sets}

      error ->
        error
    end
  end

  ## Set Element Operations

  @doc """
  List all elements in a specific set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:parse` - Parse responses into structs (default: `true`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      {:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "banned_ips")
      {:ok, elements} = NFTex.Query.list_set_elements(pid, "filter", "banned_ips", family: :inet6)
  """
  @spec list_set_elements(pid(), String.t(), String.t(), keyword()) :: result([map()])
  def list_set_elements(pid, table, set_name, opts \\ []) do
    family = resolve_family(Keyword.get(opts, :family, :inet))
    timeout = Keyword.get(opts, :timeout, 5000)
    parse = Keyword.get(opts, :parse, true)

    case Port.call(pid, {:set_elem_list, family, table, set_name}, timeout) do
      {:ok, elements} when parse ->
        {:ok, Enum.map(elements, &parse_set_element/1)}

      {:ok, elements} ->
        {:ok, elements}

      error ->
        error
    end
  end

  @doc """
  Delete elements from a set.

  ## Parameters

  - `pid` - NFTex process pid
  - `table` - Table name (string)
  - `set_name` - Set name (string)
  - `elements` - List of binary keys to delete (e.g., `[<<192, 168, 1, 100>>, <<10, 0, 0, 1>>]`)
  - `opts` - Keyword list options:
    - `:family` - Protocol family (default: `:inet`)
    - `:timeout` - Operation timeout in ms (default: 5000)

  ## Examples

      # Delete specific IPs from a blocklist
      ips = [<<192, 168, 1, 100>>, <<10, 0, 0, 50>>]
      :ok = NFTex.Query.delete_set_elements(pid, "filter", "banned_ips", ips)

      # Delete from IPv6 set
      :ok = NFTex.Query.delete_set_elements(pid, "filter", "banned_ips6", [ipv6_addr], family: :inet6)
  """
  @spec delete_set_elements(pid(), String.t(), String.t(), [binary()], keyword()) :: :ok | {:error, String.t()}
  def delete_set_elements(pid, table, set_name, elements, opts \\ []) when is_list(elements) do
    family = resolve_family(Keyword.get(opts, :family, :inet))
    timeout = Keyword.get(opts, :timeout, 5000)

    # Create a set object for deletion
    with {:ok, set_id} <- Port.call(pid, {:set_alloc}, timeout),
         :ok <- Port.call(pid, {:set_set_str, set_id, :name, set_name}, timeout),
         :ok <- Port.call(pid, {:set_set_str, set_id, :table, table}, timeout) do

      # Add all elements to be deleted
      elem_result = Enum.reduce_while(elements, :ok, fn key, :ok ->
        with {:ok, elem_id} <- Port.call(pid, {:set_elem_alloc}, timeout),
             :ok <- Port.call(pid, {:set_elem_set_data, elem_id, :key, key}, timeout),
             :ok <- Port.call(pid, {:set_elem_add, set_id, elem_id}, timeout) do
          {:cont, :ok}
        else
          error -> {:halt, error}
        end
      end)

      case elem_result do
        :ok ->
          # Send deletion command to kernel
          Port.call(pid, {:set_elem_send_to_kernel, set_id, :delete, family}, timeout)

        error ->
          error
      end
    end
  end

  ## Parsing Functions

  defp parse_table(bin) do
    [name, family_str, flags_str | _] = String.split(bin, <<0>>, trim: true)

    %{
      name: name,
      family: parse_family_int(family_str),
      flags: String.to_integer(flags_str)
    }
  end

  defp parse_chain(bin) do
    fields = String.split(bin, <<0>>, trim: true)

    case fields do
      [name, table, type, hook, prio, policy, family] ->
        %{
          name: name,
          table: table,
          type: type,
          hook: parse_hook(hook),
          priority: String.to_integer(prio),
          policy: parse_policy(policy),
          family: parse_family_int(family),
          base_chain: true
        }

      [name, table, family] ->
        %{
          name: name,
          table: table,
          family: parse_family_int(family),
          base_chain: false
        }

      _ ->
        %{raw: bin}
    end
  end

  defp parse_rule(bin) do
    fields = String.split(bin, <<0>>, trim: true)

    case fields do
      [table, chain, family, handle, position] ->
        %{
          table: table,
          chain: chain,
          family: parse_family_int(family),
          handle: String.to_integer(handle),
          position: String.to_integer(position)
        }

      _ ->
        %{raw: bin}
    end
  end

  defp parse_set(bin) do
    fields = String.split(bin, <<0>>, trim: true)

    case fields do
      [name, table, family, key_type, key_len, flags] ->
        %{
          name: name,
          table: table,
          family: parse_family_int(family),
          key_type: String.to_integer(key_type),
          key_len: String.to_integer(key_len),
          flags: String.to_integer(flags)
        }

      _ ->
        %{raw: bin}
    end
  end

  defp parse_set_element(bin) do
    [key_hex, flags_str | _] = String.split(bin, <<0>>, trim: true)

    %{
      key_hex: key_hex,
      key_ip: hex_to_ip(key_hex),
      flags: String.to_integer(flags_str)
    }
  end

  ## Helper Functions

  defp resolve_family(family) when is_atom(family) do
    Map.get(@family_map, family, 2)
  end

  defp resolve_family(family) when is_integer(family), do: family

  defp parse_family_int(str) do
    case String.to_integer(str) do
      2 -> :inet
      10 -> :inet6
      3 -> :arp
      7 -> :bridge
      5 -> :netdev
      other -> other
    end
  end

  defp parse_hook(str) do
    case String.to_integer(str) do
      0 -> :prerouting
      1 -> :input
      2 -> :forward
      3 -> :output
      4 -> :postrouting
      other -> other
    end
  end

  defp parse_policy(str) do
    case String.to_integer(str) do
      0 -> :drop
      1 -> :accept
      other -> other
    end
  end

  defp hex_to_ip(hex) when byte_size(hex) == 8 do
    # IPv4 address (4 bytes = 8 hex chars)
    with {a, ""} <- Integer.parse(String.slice(hex, 0, 2), 16),
         {b, ""} <- Integer.parse(String.slice(hex, 2, 2), 16),
         {c, ""} <- Integer.parse(String.slice(hex, 4, 2), 16),
         {d, ""} <- Integer.parse(String.slice(hex, 6, 2), 16) do
      "#{a}.#{b}.#{c}.#{d}"
    else
      _ -> hex
    end
  end

  defp hex_to_ip(hex), do: hex
end
